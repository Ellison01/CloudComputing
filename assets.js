document.addEventListener('DOMContentLoaded', () => {
    const assetForm = document.getElementById('assetForm');
    const assetTableBody = document.getElementById('assetTableBody');
    const reportOutput = document.getElementById('reportOutput');
    const generateReportButton = document.getElementById('generateReport');
    const printReportButton = document.getElementById('printReport');
  
    // Function to generate a random serial number
    const generateSerialNumber = () => {
      return 'SN-' + Math.random().toString(36).substr(2, 9).toUpperCase();
    };
  
    // Load assets from local storage
    const loadAssets = () => {
      const assets = JSON.parse(localStorage.getItem('assets')) || [];
      assetTableBody.innerHTML = '';
      assets.forEach((asset, index) => {
        addAssetToTable(asset, index);
      });
    };
  
    // Add asset to table
    const addAssetToTable = (asset, index) => {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td>${asset.name}</td>
        <td>${asset.type}</td>
        <td>${asset.serial}</td>
        <td>${asset.location}</td>
        <td>${asset.status}</td>
        <td>${asset.maintenanceDate}</td>
        <td>${asset.license}</td>
        <td><button class="btn btn-danger btn-sm delete-btn" data-index="${index}">Delete</button></td>
      `;
      assetTableBody.appendChild(row);
    };
  
    // Add asset to local storage
    const addAssetToLocalStorage = (asset) => {
      const assets = JSON.parse(localStorage.getItem('assets')) || [];
      assets.push(asset);
      localStorage.setItem('assets', JSON.stringify(assets));
    };
  
    // Remove asset from local storage
    const removeAssetFromLocalStorage = (index) => {
      const assets = JSON.parse(localStorage.getItem('assets')) || [];
      assets.splice(index, 1);
      localStorage.setItem('assets', JSON.stringify(assets));
    };
  
    // Handle form submit
    assetForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const assetName = document.getElementById('assetName').value;
      const assetType = document.getElementById('assetType').value;
      const assetSerial = generateSerialNumber(); // Generate serial number
      const assetLocation = document.getElementById('assetLocation').value;
      const assetStatus = document.getElementById('assetStatus').value;
      const assetMaintenanceDate = document.getElementById('assetMaintenanceDate').value;
      const assetLicense = document.getElementById('assetLicense').value;
      const asset = { 
        name: assetName, 
        type: assetType, 
        serial: assetSerial,
        location: assetLocation,
        status: assetStatus,
        maintenanceDate: assetMaintenanceDate,
        license: assetLicense
      };
  
      addAssetToLocalStorage(asset);
      addAssetToTable(asset, JSON.parse(localStorage.getItem('assets')).length - 1);
  
      assetForm.reset();
    });
  
    // Handle delete button click
    assetTableBody.addEventListener('click', (e) => {
      if (e.target.classList.contains('delete-btn')) {
        const index = e.target.getAttribute('data-index');
        removeAssetFromLocalStorage(index);
        loadAssets();
      }
    });
  
    // Generate report
    generateReportButton.addEventListener('click', () => {
      const assets = JSON.parse(localStorage.getItem('assets')) || [];
      let report = 'Asset Utilization Report\n\n';
      assets.forEach(asset => {
        report += `Name: ${asset.name}, Type: ${asset.type}, Location: ${asset.location}, Status: ${asset.status}, Next Maintenance: ${asset.maintenanceDate}, License: ${asset.license}\n`;
      });
      reportOutput.textContent = report;
    });
  
    // Print report
    printReportButton.addEventListener('click', () => {
      const printContent = reportOutput.textContent;
      const printWindow = window.open('', '', 'height=500,width=800');
      printWindow.document.write('<pre>' + printContent + '</pre>');
      printWindow.document.close();
      printWindow.print();
    });
  
    // Initial load of assets
    loadAssets();
  });
  