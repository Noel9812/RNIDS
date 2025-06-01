// Define socket and messages_received at global scope
var socket;
var messages_received = [];
var currentPage = 1;

$(document).ready(function () {
    // Firebase configuration
    const firebaseConfig = {
        apiKey: "AIzaSyBUJwBPUiPRM4igsgyPYsgBJxYFpkM8KvU",
        authDomain: "rnids-2025.firebaseapp.com",
        projectId: "rnids-2025",
        storageBucket: "rnids-2025.appspot.com",
        messagingSenderId: "192282235608",
        appId: "1:192282235608:web:5a3b7e200c4b1148be3dad",
        measurementId: "G-4ME3E02VQS"
    };

    // Initialize Firebase
    firebase.initializeApp(firebaseConfig);
    const db = firebase.firestore();
    const auth = firebase.auth();

    // Initialize Socket.IO connection
    socket = io.connect('http://' + document.domain + ':' + location.port + '/test');
    var ctx = document.getElementById("myChart").getContext('2d');
    var itemsPerPage = 10;

    // Load saved flows from localStorage
    loadFlowsFromLocal();

  
// Modified auth state handler
auth.onAuthStateChanged(user => {
    if (user) {
        // User is signed in
        console.log("User is signed in:", user.uid);
        
        // Check if this is a new session
        fetch('/check-session')
            .then(response => response.json())
            .then(data => {
                if (data.new_session) {
                    // Clear any existing flows for this user
                    clearAllFlowStorage();
                }
                initializeFirebaseListeners();
            })
            .catch(error => {
                console.error("Error checking session:", error);
                initializeFirebaseListeners();
            });
    } else {
        // User signed out - clear flows
        clearAllFlowStorage();
    }
});

    // Function to initialize all Firebase listeners
    function initializeFirebaseListeners() {
        updateNotificationBadge();
        updateHighRiskCounter();
        setupGlobalStatsListener();
    }

    // Initialize Chart.js
    var myChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Flow Count',
                data: [],
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                borderColor: 'rgba(75, 192, 192, 1)',
                borderWidth: 1
            }]
        },
        options: {
            legend: { display: false },
            scales: {
                yAxes: [{ ticks: { beginAtZero: true } }]
            }
        }
    });

    // Setup real-time stats listener with enhanced error handling
    function setupGlobalStatsListener() {
        db.collection("global_stats").doc("realtime")
            .onSnapshot((doc) => {
                try {
                    const data = doc.data();
                    if (data) {
                        $("#active-sessions").text(data.active_sessions || 0);
                        $("#current-threats").text(data.threats_last_hour || 0);
                        
                        // Update chart with new data if available
                        if (myChart && data.active_sessions) {
                            // Only update if we don't have more detailed data already
                            if (myChart.data.datasets[0].data.length <= 1) {
                                myChart.data.datasets[0].data = [data.active_sessions];
                                myChart.update();
                            }
                        }
                    }
                } catch (error) {
                    console.error("Error processing realtime stats:", error);
                    toastr.error("Unable to get real-time statistics");
                }
            }, (error) => {
                handleFirebaseError(error, "global_stats");
            });
    }

    // Risk level notification function with enhanced detection
    function checkRiskLevel(riskLevel, flowData) {
        // Get classification from the data
        const classification = flowData[flowData.length - 3]; // Classification is third from the end
        const isNonBenign = classification !== "Benign";
        const isHighRisk = riskLevel === "high" || riskLevel === "very_high";
        
        // Update high-risk flows counter
        if (isHighRisk) {
            let highRiskCount = parseInt($('#high-risk-flows').text()) || 0;
            $('#high-risk-flows').text(highRiskCount + 1);
        }
        
        // Show notification for high risk or non-benign flows
        if (isHighRisk || isNonBenign) {
            // Set notification styling based on risk level
            let toastrType = 'warning';
            let alertTitle = 'Security Alert';
            
            if (riskLevel === "very_high") {
                toastrType = 'error';
                alertTitle = 'CRITICAL SECURITY ALERT';
            } else if (!isHighRisk && isNonBenign) {
                toastrType = 'info';
                alertTitle = 'Suspicious Flow Detected';
            }
            
            // Create rich notification content
            const message = `
                <strong>${classification}</strong> traffic detected!<br>
                <span class="notification-detail">Source: ${flowData[1]}</span><br>
                <span class="notification-detail">Destination: ${flowData[3]}</span><br>
                <span class="notification-detail">Protocol: ${flowData[5]}</span><br>
                <span class="notification-detail">Risk Level: ${riskLevel.replace('_', ' ')}</span>
            `;
            
            // Configure and show Toastr notification
            toastr.options = {
                closeButton: true,
                progressBar: true,
                timeOut: isHighRisk ? 10000 : 5000,
                extendedTimeOut: 3000,
                positionClass: "toast-top-right",
                showEasing: "swing",
                hideEasing: "linear",
                showMethod: "fadeIn",
                hideMethod: "fadeOut",
                escapeHtml: false
            };
            
            // Show appropriate notification type
            toastr[toastrType](message, alertTitle);

            // Play alert sound for high risk
            if (isHighRisk) {
                const alertSound = document.getElementById("alert-sound");
                if (alertSound) {
                    // Reset the audio element before playing
                    alertSound.pause();
                    alertSound.currentTime = 0;
                    alertSound.volume = 0.7;    
                    
                    // Play with error handling
                    const playPromise = alertSound.play();
                    if (playPromise !== undefined) {
                        playPromise.catch(e => {
                            console.error("Failed to play alert sound:", e);
                            // Try again after user interaction
                            $(document).one('click', function() {
                                alertSound.play().catch(e => console.error("Still failed to play sound:", e));
                            });
                        });
                    }
                } else {
                    console.error("Alert sound element not found");
                }
            }
            
            // Send notification to Firestore
            if (firebase.apps.length) {
                db.collection("notifications").add({
                    type: isHighRisk ? "high_risk_flow" : "suspicious_flow",
                    risk_level: riskLevel,
                    classification: classification,
                    source_ip: flowData[1],
                    dest_ip: flowData[3],
                    protocol: flowData[5],
                    timestamp: firebase.firestore.FieldValue.serverTimestamp(),
                    viewed: false
                }).catch(error => {
                    console.error("Error sending notification:", error);
                });
            }
        }
    }

    // Update table with pagination
    function updateTable(page) {
        var start = (page - 1) * itemsPerPage;
        var end = start + itemsPerPage;
        var paginatedData = messages_received.slice(start, end);
    
        var messages_string = `
            <tr>
                <th>Flow ID</th>
                <th>Src IP</th>
                <th>Src Port</th>
                <th>Dst IP</th>
                <th>Dst Port</th>
                <th>Protocol</th>
                <th>Flow Start</th>
                <th>Flow End</th>
                <th>App Name</th>
                <th>PID</th>
                <th>Prediction</th>
                <th>Prob</th>
                <th>Risk</th>
                <th>Details</th>
            </tr>`;
    
        for (var i = 0; i < paginatedData.length; i++) {
            var riskLevel = paginatedData[i][paginatedData[i].length - 1].toLowerCase().replace(" ", "_");
            var riskText = riskLevel.replace("_", " "); // For display
            var rowClass = riskLevel.includes("high") ? 'high-risk-row' : '';
            
            messages_string += `<tr class="${rowClass}" data-risk="${riskLevel}">`;
            for (var j = 0; j < paginatedData[i].length; j++) {
                messages_string += `<td>${paginatedData[i][j].toString()}</td>`;
            }
            messages_string += `<td><a href="/detail?flow_id=${paginatedData[i][0]}" class="btn btn-sm btn-primary">Details</a></td></tr>`;
        }
        $('#details').html(messages_string);
    
        // Update pagination
        var totalPages = Math.ceil(messages_received.length / itemsPerPage);
        var paginationHtml = '';
        for (var p = 1; p <= totalPages; p++) {
            paginationHtml += `
                <li class="page-item${p === currentPage ? ' active' : ''}">
                    <a class="page-link" href="#" data-page="${p}">${p}</a>
                </li>`;
        }
        $('#pagination').html(paginationHtml);
        
        // Update filtered count
        updateFilteredCount();
    }
    
    // Update filtered count function
    function updateFilteredCount() {
        const visibleRows = $("#details tr:visible").length - 1; // -1 for header
        $("#filtered-count").text(visibleRows);
    }

    // Handle logout
   // Enhanced logout handler
$(document).on('click', '#logout-button', function(e) {
    e.preventDefault();
    
    // Show loading indicator
    toastr.info("Logging out...", "", {timeOut: 2000});
    
    // Clear local storage first
    if (clearAllFlowStorage()) {
        // Then sign out from Firebase
        firebase.auth().signOut().then(() => {
            // Optionally call server-side cleanup
            fetch('/clear-local-flows')
                .then(response => response.json())
                .then(data => {
                    console.log("Server cleanup response:", data);
                    // Redirect to logout endpoint
                    window.location.href = '/logout';
                })
                .catch(error => {
                    console.error("Error calling server cleanup:", error);
                    // Still proceed with logout
                    window.location.href = '/logout';
                });
        }).catch(error => {
            console.error("Sign out error:", error);
            toastr.error("Logout failed. Please try again.");
        });
    } else {
        toastr.error("Failed to clear local data. Logout aborted.");
    }
});

    
    // Handle pagination clicks
    $(document).on('click', '.page-link', function (e) {
        e.preventDefault();
        currentPage = $(this).data('page');
        updateTable(currentPage);
    });

    // Setup Socket.IO event handlers
    socket.on('newresult', function (msg) {
        try {
            // Add to messages array with pagination support
            if (messages_received.length >= 100) {
                messages_received.shift();
            }
            messages_received.push(msg.result);
            updateTable(currentPage);
            
            // Save to localStorage for persistence across refreshes
            saveFlowsToLocal();

            // Check risk level and notify
            checkRiskLevel(msg.risk_level, msg.result);

            // Update chart
            var chartLabels = [];
            var chartData = [];
            for (var i = 0; i < msg.ips.length; i++) {
                chartLabels.push(msg.ips[i].SourceIP);
                chartData.push(msg.ips[i].count);
            }
            myChart.data.labels = chartLabels;
            myChart.data.datasets[0].data = chartData;
            myChart.update();
            
            // Debug information
            console.log("Received classification:", msg.classification);
            
            // Increment current threats counter (for any non-benign flows)
            if (msg.classification && msg.classification !== "Benign") {
                console.log("Non-benign traffic detected:", msg.classification);
                let currentThreats = parseInt($("#current-threats").text()) || 0;
                $("#current-threats").text(currentThreats + 1);
            }
        } catch (error) {
            console.error("Error processing new result:", error);
        }
    });

    // Handle Socket.IO connection errors
    socket.on('connect_error', function (error) {
        console.error('Socket.IO connection error:', error);
        toastr.error("Connection lost. Attempting to reconnect...");
        setTimeout(function() {
            socket.connect();
        }, 3000);
    });

    // Handle reconnection
    socket.on('reconnect', function() {
        toastr.success("Connection reestablished", "Success");
    });

    // Notification badge update
    function updateNotificationBadge() {
        db.collection("notifications")
            .where("viewed", "==", false)
            .onSnapshot((snapshot) => {
                const count = snapshot.size;
                const badge = $("#notification-badge");
                
                if (count > 0) {
                    badge.text(count).show();
                } else {
                    badge.hide();
                }
            }, (error) => {
                handleFirebaseError(error, "notification_badge");
            });
    }

    // Function to track high-risk flows
    function updateHighRiskCounter() {
        if (firebase.apps.length) {
            db.collection("malicious_flows")
                .where("risk.level", "in", ["high", "very_high"])
                .onSnapshot((snapshot) => {
                    try {
                        $("#high-risk-flows").text(snapshot.size || 0);
                    } catch (error) {
                        console.error("Error updating high risk counter:", error);
                    }
                }, (error) => {
                    handleFirebaseError(error, "high_risk_counter");
                });
        }
    }

    // Improved Risk filter handling
    $("#risk-filter").on("change", function() {
        const selectedRisk = $(this).val().toLowerCase();
        
        // Show all rows first (including header)
        $("#details tr").show();
        
        if (selectedRisk !== "all") {
            // Hide non-matching rows (skip header row)
            $("#details tr:not(:first-child)").each(function() {
                const riskCell = $(this).find("td:nth-child(13)").text().toLowerCase();
                const normalizedRisk = selectedRisk.replace("_", " ");
                
                if (!riskCell.includes(normalizedRisk)) {
                    $(this).hide();
                }
            });
        }
        
        // Update count of visible rows
        updateFilteredCount();
    });

    // Fixed download report function
  $("#download-report").on("click", function() {
    try {
        // Get the currently selected risk filter
        const selectedRisk = $("#risk-filter").val().toLowerCase();
        
        // Collect all data from messages_received (not just visible rows)
        let filteredData = messages_received;
        
        // Filter based on risk level if not "all"
        if (selectedRisk !== "all") {
            const normalizedRisk = selectedRisk.replace("_", " ");
            filteredData = messages_received.filter(row => {
                const riskCell = row[row.length - 1].toLowerCase();
                return riskCell.includes(normalizedRisk);
            });
        }

        if (filteredData.length === 0) {
            toastr.warning("No data to download with current filter");
            return;
        }

        // Get headers
        const headers = [
            'Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 
            'Protocol', 'Flow Start', 'Flow End', 'App Name', 'PID',
            'Prediction', 'Prob', 'Risk'
        ];

        // Build CSV content
        const csvRows = [headers.join(",")];
        
        filteredData.forEach(row => {
            const rowData = [];
            // Get all columns except the Details button (first 13 columns)
            for (let j = 0; j < 13; j++) {
                // Clean text content for CSV
                let text = String(row[j]).replace(/<[^>]*>/g, '');
                text = text.replace(/,/g, ' '); // Replace commas with spaces
                text = text.replace(/\n/g, ' '); // Remove newlines
                rowData.push(`"${text}"`); // Wrap in quotes to handle special chars
            }
            csvRows.push(rowData.join(","));
        });

        // Create and download file
        const csvContent = csvRows.join("\n");
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        
        // Use filter level in filename
        const filename = selectedRisk === "all" ? 
            `rnids-full-report-${timestamp}.csv` : 
            `rnids-${selectedRisk}-risk-${timestamp}.csv`;
            
        link.setAttribute("href", url);
        link.setAttribute("download", filename);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        toastr.success(`Downloaded ${filteredData.length} rows`);
    } catch (e) {
        console.error("Error downloading report:", e);
        toastr.error("Failed to download report: " + e.message);
    }
});

    // Notification panel toggler
    $("#notifications-link").on("click", function(e) {
        e.preventDefault();
        // Implementation for notifications panel would go here
        toastr.info("Notifications panel functionality coming soon");
    });
    
    // Initialize filtered count on page load
    setTimeout(updateFilteredCount, 1000);

    // Improve error handling for Firebase operations
    function handleFirebaseError(error, context) {
        console.error(`Firebase error in ${context}:`, error);
        
        // Only show one error notification per type to avoid spamming
        const errorKey = `shown_${context}_error`;
        if (!window[errorKey]) {
            if (error.code === 'permission-denied') {
                toastr.warning("Firebase permission error. Please check authentication.", "Access Denied");
            } else {
                toastr.error("Error connecting to database. Some features may not work.", "Connection Error");
            }
            window[errorKey] = true;
        }
    }
});


// Function to save flow data to localStorage with user scope
function saveFlowsToLocal() {
    try {
        const userId = firebase.auth().currentUser?.uid || 'anonymous';
        const key = `rnids_flows_${userId}`;
        localStorage.setItem(key, JSON.stringify(messages_received));
        console.log(`Saved ${messages_received.length} flows to local storage for user ${userId}`);
    } catch (e) {
        console.error("Failed to save flows to localStorage:", e);
    }
}

// Add this function to clear all flow-related data
function clearAllFlowStorage() {
    try {
        // Clear all possible flow storage keys
        localStorage.removeItem('rnids_flows');
        
        // Clear user-specific flows if exists
        const userId = firebase.auth().currentUser?.uid || 'anonymous';
        localStorage.removeItem(`rnids_flows_${userId}`);
        
        // Clear in-memory storage
        messages_received = [];
        
        // Reset the table display
        updateTable(1);
        
        console.log("Cleared all flow data from storage");
        return true;
    } catch (e) {
        console.error("Error clearing flow storage:", e);
        return false;
    }
}


// Function to load flow data from localStorage with user scope
function loadFlowsFromLocal() {
    try {
        const userId = firebase.auth().currentUser?.uid || 'anonymous';
        const key = `rnids_flows_${userId}`;
        const savedFlows = localStorage.getItem(key);
        
        if (savedFlows) {
            messages_received = JSON.parse(savedFlows);
            console.log(`Loaded ${messages_received.length} flows from local storage for user ${userId}`);
            if (typeof updateTable === 'function') {
                updateTable(currentPage);
            }
        }
    } catch (e) {
        console.error("Failed to load flows from localStorage:", e);
    }
}

// Add this new function to clear flows for the current user
function clearUserFlows() {
    try {
        const userId = firebase.auth().currentUser?.uid || 'anonymous';
        const key = `rnids_flows_${userId}`;
        localStorage.removeItem(key);
        console.log(`Cleared flows for user ${userId}`);
        messages_received = []; // Clear in-memory storage too
    } catch (e) {
        console.error("Failed to clear user flows:", e);
    }
}
