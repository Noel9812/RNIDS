$(document).ready(function () {
    var socket = io.connect('http://' + document.domain + ':' + location.port + '/test');
    var messages_received = [];
    var ctx = document.getElementById("myChart").getContext('2d');
    var itemsPerPage = 10; // Number of items per page
    var currentPage = 1;

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

    // Function to check risk level and trigger Toastr notification
    function checkRiskLevel(riskLevel) {
        if (riskLevel.includes("High") || riskLevel.includes("Very High")) {
            // Show Toastr notification
            toastr.warning("Warning: High Risk Detected!\nRisk Level: " + riskLevel, "Risk Alert", {
                timeOut: 5000, // Display for 5 seconds
                closeButton: true,
                progressBar: true,
                positionClass: "toast-top-right"
            });

            // Play alert sound
            var alertSound = document.getElementById("alert-sound");
            alertSound.play();
        }
    }

    // Function to update table with pagination
    function updateTable(page) {
        var start = (page - 1) * itemsPerPage;
        var end = start + itemsPerPage;
        var paginatedData = messages_received.slice(start, end);

        var messages_string = '<tr><th>Flow ID</th><th>Src IP</th><th>Src Port</th><th>Dst IP</th><th>Dst Port</th><th>Protocol</th><th>Flow Start Time</th><th>Flow Last Seen</th><th>App Name</th><th>PID</th><th>Prediction</th><th>Prob</th><th>Risk</th><th>Details</th></tr>';

        for (var i = 0; i < paginatedData.length; i++) {
            var riskLevel = paginatedData[i][paginatedData[i].length - 1]; // Assuming risk level is the last element
            var rowClass = riskLevel.includes("High") || riskLevel.includes("Very High") ? 'high-risk-row' : '';
            messages_string += '<tr class="' + rowClass + '">';
            for (var j = 0; j < paginatedData[i].length; j++) {
                messages_string += '<td>' + paginatedData[i][j].toString() + '</td>';
            }
            messages_string += '<td><a href="/detail?flow_id=' + paginatedData[i][0].toString() + '">Detail</a></td></tr>';
        }
        $('#details').html(messages_string);

        // Update pagination
        var totalPages = Math.ceil(messages_received.length / itemsPerPage);
        var paginationHtml = '';
        for (var p = 1; p <= totalPages; p++) {
            paginationHtml += '<li class="page-item' + (p === currentPage ? ' active' : '') + '"><a class="page-link" href="#" data-page="' + p + '">' + p + '</a></li>';
        }
        $('#pagination').html(paginationHtml);
    }

    // Handle pagination clicks
    $(document).on('click', '.page-link', function (e) {
        e.preventDefault();
        currentPage = $(this).data('page');
        updateTable(currentPage);
    });

    // Receive details from server
    socket.on('newresult', function (msg) {
        console.log('Received newresult event:', msg);
        if (messages_received.length >= 100) { // Limit to 100 records for performance
            messages_received.shift();
        }
        messages_received.push(msg.result);
        console.log("Updated messages_received:", messages_received); // Log the updated array
        updateTable(currentPage);

        // Extract risk level from the result
        var riskLevel = msg.result[msg.result.length - 1]; // Assuming risk level is the last element
        checkRiskLevel(riskLevel);

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
    });

    // Handle Socket.IO connection errors
    socket.on('connect_error', function (error) {
        console.error('Socket.IO connection error:', error);
        // Optionally, attempt to reconnect
        setTimeout(function() {
            socket.connect();
        }, 1000);
    });

    // Function to filter data based on risk level
    function filterDataByRiskLevel(data, riskLevels) {
        return data.filter(function (row) {
            var rowRiskLevel = row[row.length - 1]; // Assuming risk level is the last element
            return riskLevels.includes(rowRiskLevel);
        }).map(row => {
            // Ensure each row has exactly 13 elements
            if (row.length < 13) {
                // Pad missing elements with empty strings
                while (row.length < 13) {
                    row.push("");
                }
            } else if (row.length > 13) {
                // Trim extra elements
                row = row.slice(0, 13);
            }
            return row;
        });
    }

    // Function to generate PDF report
    function generatePDFReport(data) {
        console.log("Filtered Data for PDF:", data); // Log the data for debugging

        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();

        // Add title
        doc.setFontSize(18);
        doc.text("Network Intrusion Detection Report", 14, 22);

        // Export chart as image
        const chartCanvas = document.getElementById("myChart");
        const chartImage = chartCanvas.toDataURL("image/png");

        // Add chart image to PDF
        doc.addImage(chartImage, "PNG", 14, 30, 180, 100); // Adjust position and size as needed

        // Prepare table data
        var tableData = data.map(row => [
            row[0], // Flow ID
            row[1], // Src IP
            row[2], // Src Port
            row[3], // Dst IP
            row[4], // Dst Port
            row[5], // Protocol
            row[6], // Flow Start Time
            row[7], // Flow Last Seen
            row[8], // App Name
            row[9], // PID
            row[10], // Prediction
            row[11], // Prob
            row[12], // Risk
        ]);

        console.log("Table Data for PDF:", tableData); // Log the table data for debugging

        // Add table to PDF
        doc.autoTable({
            head: [["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Flow Start Time", "Flow Last Seen", "App Name", "PID", "Prediction", "Prob", "Risk"]],
            body: tableData,
            startY: 140, // Start table below the chart
            theme: "grid", // Add grid styling
            styles: {
                fontSize: 10, // Smaller font size for table content
                cellPadding: 2, // Reduce cell padding
            },
            headStyles: {
                fillColor: [214, 66, 6], // Burnt orange header
                textColor: [255, 255, 255], // White text
            },
        });

        // Save the PDF
        doc.save("RNIDS_report.pdf");
    }

    // Handle download button click
    $("#download-report").on("click", function () {
        var selectedRiskLevel = $("#risk-filter").val();
        var riskLevels = selectedRiskLevel === "All" ? ["Medium", "High", "Very High"] : [selectedRiskLevel];

        // Filter data based on selected risk level
        var filteredData = filterDataByRiskLevel(messages_received, riskLevels);

        // Generate and download PDF report
        generatePDFReport(filteredData);
    });
})