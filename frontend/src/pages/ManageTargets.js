import React, { useState, useEffect } from 'react';
import axiosInstance from '../components/axiosConfig';
import { useNavigate } from 'react-router-dom';
import '../css/components/ManageTargets.css';

const ManageTargets = () => {
    const [targets, setTargets] = useState([]);
    const [searchKeyword, setSearchKeyword] = useState('');
    const [selectedTargets, setSelectedTargets] = useState([]);
    const [currentPage, setCurrentPage] = useState(1);
    const [itemsPerPage, setItemsPerPage] = useState(10);
    const [newTarget, setNewTarget] = useState({ domain: '', rootDomain: '' });
    const [sortedTargets, setSortedTargets] = useState(targets);
    const [sortConfig, setSortConfig] = useState({ key: '', direction: 'none' });
    const [editTargets, setEditTargets] = useState({});
    const navigate = useNavigate();
    const [csvFile, setCSVFile] = useState(null);
    const [shodanInput, setShodanInput] = useState('');
    const [filterValues, setFilterValues] = useState({
        domain: '',
        rootDomain: '',
        openPorts: '',
        tag: ''
    });
// Convert filter values to strings to ensure no type errors
    const domainFilter = filterValues.domain ? String(filterValues.domain).toLowerCase() : '';
    const rootDomainFilter = filterValues.rootDomain ? String(filterValues.rootDomain).toLowerCase() : '';
    const openPortsFilter = filterValues.openPorts ? String(filterValues.openPorts).toLowerCase() : '';
    const tagFilter = filterValues.tag ? String(filterValues.tag).toLowerCase() : '';

    // Apply filtering
    const filteredTargets = targets.filter(target => {
        // Ensure domain and rootDomain are strings before applying filters
        const domainMatches = target.domain && typeof target.domain === 'string' && target.domain.toLowerCase().includes(domainFilter);
        const rootDomainMatches = target.rootDomain && typeof target.rootDomain === 'string' && target.rootDomain.toLowerCase().includes(rootDomainFilter);
    
        // Handle ports: ensure it's an array and each element is a string before applying filters
        const portsMatches = Array.isArray(target.ports) && target.ports.some(port => 
            typeof port === 'string' && port.toLowerCase().includes(openPortsFilter)
        );
    
        // Handle tag: ensure it's an array and each element is a string before applying filters
        const tagMatches = Array.isArray(target.tag) && target.tag.some(tag => 
            typeof tag === 'string' && tag.toLowerCase().includes(tagFilter)
        );
    
        // Return true only if all conditions match (adjust depending on your logic)
        return (domainFilter === '' || domainMatches) && 
               (rootDomainFilter === '' || rootDomainMatches) && 
               (openPortsFilter === '' || portsMatches) && 
               (tagFilter === '' || tagMatches);
    });
    
    
    useEffect(() => {
        fetchTargets();
    }, []);

    // handle all event ---------------------------------------------
    const handleSort = (key) => {
        let direction = 'ascending';
        if (sortConfig.key === key && sortConfig.direction === 'ascending') {
            direction = 'descending';
        } else if (sortConfig.key === key && sortConfig.direction === 'descending') {
            direction = 'none';
        } else {
            direction = 'ascending';
        }
        setSortConfig({ key, direction });
    
        if (direction === 'none') {
            setSortedTargets(targets);
        } else {
            const sortedData = [...sortedTargets].sort((a, b) => {
                if (key === 'createdAt') {
                    const dateA = new Date(a[key].$date);
                    const dateB = new Date(b[key].$date);
                    return direction === 'ascending' ? dateA - dateB : dateB - dateA;
                } else if (typeof a[key] === 'string') {
                    const stringA = a[key].toLowerCase();
                    const stringB = b[key].toLowerCase();
                    return direction === 'ascending' ? stringA.localeCompare(stringB) : stringB.localeCompare(stringA);
                } else if (typeof a[key] === 'number') {
                    
                }
                return 0;
            });
            setSortedTargets(sortedData);
        }
    };

    const fetchTargets = async () => {
        try {
            const response = await axiosInstance.get('/api/targets');
            setTargets(response.data);
        } catch (error) {
            console.error("Failed to fetch targets", error);
        }
    };

    const handleSearch = async (e) => {
        e.preventDefault();
        try {
            const response = await axiosInstance.get(`/api/targets/search?keyword=${searchKeyword}`);
            setTargets(response.data);
        } catch (error) {
            console.error("Failed to search targets", error);
        }
    };

    const handleVisualize = () => {
        navigate('/targets/visualize', { state: { targets: sortedTargets } });
    };

    const handleSelectTarget = (targetId) => {
        const target = filteredTargets.find(t => t._id.$oid === targetId);
        if (selectedTargets.includes(targetId)) {
            setSelectedTargets(selectedTargets.filter(id => id !== targetId));
            setEditTargets({
                ...editTargets,
                [targetId]: { ...editTargets[targetId], ...target }
            });
        } else {
            setSelectedTargets([...selectedTargets, targetId]);
            setEditTargets({
                ...editTargets,
                [targetId]: target
            });
        }
    };

    const handleSelectAllTargets = () => {
        //If all targets in filteredTargets is selected then unselect it
        if (selectedTargets.length === filteredTargets.length) {
            setSelectedTargets([]);
        } else {
            // Pick all targets in filteredTargets
            setSelectedTargets(filteredTargets.map(target => target._id.$oid));
        }
    };

    const handleFindSubdomains = async () => {
        try {
            await axiosInstance.post('/api/targets/subfinder', { targets: selectedTargets });
            alert("Subdomain initiated, visit Job Manager for detail");
        } catch (error) {
            console.error("Failed to find subdomains", error);
        }
    };

    const handleDeleteTargets = async () => {
        try {
            await axiosInstance.post('/api/targets/delete', { targets: selectedTargets });
            fetchTargets(); // Refresh the target list
            setSelectedTargets([]);
        } catch (error) {
            console.error("Failed to delete targets", error);
        }
    };

    const handlePortScanTargets = async () => {
        try {
            await axiosInstance.post('/api/targets/nmap', { ids: selectedTargets });
            alert("Nmap initiated, visit Job Manager for detail");
            fetchTargets(); // Refresh the target list
            setSelectedTargets([]);
        } catch (error) {
            console.error("Failed to scan port of targets", error);
        }
    };

    const handleAddTarget = async (e) => {
        e.preventDefault();
        try {
            await axiosInstance.post('/api/targets', newTarget);
            fetchTargets(); // Refresh the target list
            setNewTarget({ domain: '', rootDomain: '' });
        } catch (error) {
            if (error.response && error.response.status === 409) {
                alert("Duplicate domain");
            } else {
                console.error("Failed to add target", error);
            }
        }
    };

    const handleNucleiScan = async () => {
        try {
            await axiosInstance.post('/api/targets/nuclei', { ids: selectedTargets });
            alert("Nuclei scan initiated");
        } catch (error) {
            console.error("Failed to initiate Nuclei scan", error);
        }
    };

    const handleReverseDNSScan = async () => {
        try {
            await axiosInstance.post('/api/targets/reverse-dns', { ids: selectedTargets });
            alert("Reverse IP Lookup initiated");
        } catch (error) {
            console.error("Failed to initiate Reverse IP Lookup", error);
        }
    };

    const handleItemsPerPageChange = (e) => {
        setItemsPerPage(Number(e.target.value));
        setCurrentPage(1); // Reset to first page on items per page change
    };

    // const totalPages = Math.ceil(targets.length / itemsPerPage);

    // const currentTargets = targets.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);
    const currentTargets = filteredTargets.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

    const renderPageNumbers = () => {
        const totalPages = Math.ceil(filteredTargets.length / itemsPerPage);  
        const pageNumbers = [];
        const maxPagesToShow = 5;
        const halfPagesToShow = Math.floor(maxPagesToShow / 2);
        
        let startPage = Math.max(currentPage - halfPagesToShow, 1);
        let endPage = Math.min(currentPage + halfPagesToShow, totalPages);
    
        if (currentPage <= halfPagesToShow) {
            endPage = Math.min(maxPagesToShow, totalPages);
        }
    
        if (currentPage + halfPagesToShow >= totalPages) {
            startPage = Math.max(totalPages - maxPagesToShow + 1, 1);
        }
    
        // Add start ellipsis if necessary
        if (startPage > 1) {
            pageNumbers.unshift(<span key="start-ellipsis">...</span>);
            pageNumbers.unshift(
                <button key={1} onClick={() => setCurrentPage(1)}>
                    1
                </button>
            );
        }
    
        // Add page numbers
        for (let i = startPage; i <= endPage; i++) {
            pageNumbers.push(
                <button
                    key={i}
                    onClick={() => setCurrentPage(i)}
                    className={i === currentPage ? 'active' : ''}
                >
                    {i}
                </button>
            );
        }
    
        // Add end ellipsis if necessary
        if (endPage < totalPages) {
            pageNumbers.push(<span key="end-ellipsis">...</span>);
            pageNumbers.push(
                <button key={totalPages} onClick={() => setCurrentPage(totalPages)}>
                    {totalPages}
                </button>
            );
        }
    
        return pageNumbers;
    };    

    const handleEditTarget = (id, field, value) => {
        setEditTargets(prevTargets => ({
            ...prevTargets,
            [id]: {
                ...prevTargets[id],
                [field]: field === 'tag' 
                    ? (typeof value === 'string' ? value.split(',').map(item => item.trim()) : value)
                    : value,
            },
        }));
    };

    const handleSave = async () => {
        const updatedTargets = Object.keys(editTargets).map(targetId => ({
            _id: targetId,
            domain: editTargets[targetId].domain,
            rootDomain: editTargets[targetId].rootDomain,
            tag: Array.isArray(editTargets[targetId].tag) 
                ? editTargets[targetId].tag 
                : editTargets[targetId].tag 
                    ? editTargets[targetId].tag.split(',').map(item => item.trim()) 
                    : [],
            totalVulnerability: editTargets[targetId].totalVulnerability || 0,
            totalSubDomains: editTargets[targetId].totalSubDomains || 0,
            ports: Array.isArray(editTargets[targetId].ports) 
                ? editTargets[targetId].ports 
                : editTargets[targetId].ports 
                    ? editTargets[targetId].ports.split(',').map(item => item.trim()) 
                    : [],
            lastUpdate: new Date().toISOString(), 
        }));              
        try {
            await axiosInstance.post('/api/targets/update', updatedTargets);
            alert("Targets updated successfully");
            setEditTargets({});
            fetchTargets();
        } catch (error) {
            console.error("Failed to update targets", error);
        }
    };    

    const handleCSVFile = (event) => {
        setCSVFile(event.target.files[0]);
    };
    const handleImportCSV = async (event) => {
        event.preventDefault();
      
        if (!csvFile) {
          alert("Please select a CSV file");
          return;
        }
      
        try {
          const formData = new FormData();
          formData.append("csv", csvFile);
      
          const response = await axiosInstance.post("/api/targets/import", formData, {
            headers: {
              "Content-Type": "multipart/form-data",
            },
          });
      
          alert(response.data.message);
        } catch (error) {
          console.error("Failed to import targets from CSV", error);
          alert("Failed to import targets from CSV");
        }
    };

    const handleShodanSubmit = (e) => {
        e.preventDefault();
        axiosInstance
            .post('/api/targets/shodan', { shodanQuery: shodanInput })
            .then((response) => {
                // Show response data in an alert
                alert(`Shodan Response: ${JSON.stringify(response.data)}`);
            })
            .catch((error) => {
                // Show error message in an alert
                alert(`Error: ${error.message}`);
            });
    };
    
    // Update filter values
    const handleFilterChange = (field, value) => {
        setFilterValues(prevValues => ({ ...prevValues, [field]: value }));
    };
    
// Autocomplete suggestions based on the column's unique values
const getSuggestions = (field) => {
    let suggestions = [];
    
    switch (field) {
        case 'domain':
            suggestions = [...new Set(targets.map(t => t.domain))];
            break;
        case 'rootDomain':
            suggestions = [...new Set(targets.map(t => t.rootDomain))];
            break;
        case 'ports':
            // Flatten ports array and ensure it's a string before comparison
            suggestions = [...new Set(targets.flatMap(t => t.ports).filter(port => typeof port === 'string'))];
            break;
        case 'tag':
            // Flatten tag array and ensure it's a string before comparison
            suggestions = [...new Set(targets.flatMap(t => t.tag).filter(tag => typeof tag === 'string'))];
            break;
        default:
            break;
    }

    // Ensure filterValues[field] is a string before using toLowerCase()
    const filterValue = filterValues[field] ? String(filterValues[field]).toLowerCase() : '';
    
    return suggestions.filter(suggestion => suggestion && typeof suggestion === 'string' && suggestion.toLowerCase().includes(filterValue));
};

    
    return (
        <div>
            <h2>Targets Management</h2>
            <div className="search-shodan-container">
                <form onSubmit={handleSearch} className="search-form">
                    <input
                        type="text"
                        placeholder="Search..."
                        value={searchKeyword}
                        onChange={(e) => setSearchKeyword(e.target.value)}
                    />
                    <button type="submit">Search</button>
                    <button type="button" onClick={handleFindSubdomains} disabled={selectedTargets.length === 0}>
                        Find Subdomain
                    </button>
                    <button onClick={handleNucleiScan} disabled={selectedTargets.length === 0}>
                        Nuclei Scan
                    </button>
                    
                    <button onClick={handleReverseDNSScan} disabled={selectedTargets.length === 0}>
                        Reverse IP Lookup
                    </button>
                    <button type="button" onClick={handlePortScanTargets} disabled={selectedTargets.length === 0}>
                        Nmap Scan
                    </button>
                    <button type="button" onClick={handleVisualize} disabled={targets.length === 0}>
                        Visualize
                    </button>
                    <button type="button" onClick={handleDeleteTargets} disabled={selectedTargets.length === 0}>
                        Delete
                    </button>
                </form>
                <form onSubmit={handleShodanSubmit} className="shodan-form">
                        <input
                            type="text"
                            placeholder="Shodan query..."
                            value={shodanInput}
                            onChange={(e) => setShodanInput(e.target.value)}
                        />
                        <button type="submit">Shodan Search</button>
                </form>
            </div>

            <div className="add-target-form-container">
                <form onSubmit={handleAddTarget} className="add-target-form">
                    <input
                        type="text"
                        placeholder="Domain"
                        value={newTarget.domain}
                        onChange={(e) => setNewTarget({ ...newTarget, domain: e.target.value })}
                        required
                    />
                    <input
                        type="text"
                        placeholder="Root Domain"
                        value={newTarget.rootDomain}
                        onChange={(e) => setNewTarget({ ...newTarget, rootDomain: e.target.value })}
                        required
                    />
                    <button type="submit">Add Target</button>
                </form>
                <form onSubmit={handleImportCSV} className="add-target-form">

                    <input type="file" accept=".csv" onChange={handleCSVFile} />
                    <a href="/import_targets_template.csv" download className="download-template">Import Template</a>
                    <button type="submit">Import Targets (CSV)</button>

                </form>
            </div>
            
            <div className="pagination-options">
                <label>
                    Items per page:
                    <select value={itemsPerPage} onChange={handleItemsPerPageChange}>
                        <option value={10}>10</option>
                        <option value={15}>15</option>
                        <option value={50}>50</option>
                    </select>
                </label>
                <label>|</label>
                <label>
                    Total : {filteredTargets.length}
                </label>
            </div>

            <table className="targets-table">
                <thead>
                    <tr>
                        <th>
                            <input
                                type="checkbox"
                                checked={selectedTargets.length === targets.length}
                                onChange={handleSelectAllTargets}
                            />
                        </th>
                        <th>ID</th>
                        <th>
                            Domain/IP
                            <input
                                type="text"
                                placeholder="Filter by Domain"
                                value={filterValues.domain}
                                onChange={(e) => handleFilterChange('domain', e.target.value)}
                                list="domainSuggestions"
                            />
                            <datalist id="domainSuggestions">
                                {getSuggestions('domain').map((suggestion, index) => (
                                    <option key={index} value={suggestion} />
                                ))}
                            </datalist>
                        </th>
                        <th>
                            Root Domain
                            <input
                                type="text"
                                placeholder="Filter by Root Domain"
                                value={filterValues.rootDomain}
                                onChange={(e) => handleFilterChange('rootDomain', e.target.value)}
                                list="rootDomainSuggestions"
                            />
                            <datalist id="rootDomainSuggestions">
                                {getSuggestions('rootDomain').map((suggestion, index) => (
                                    <option key={index} value={suggestion} />
                                ))}
                            </datalist>
                        </th>
                        <th>
                            Open Ports
                            <input
                                type="text"
                                placeholder="Filter by Ports"
                                value={filterValues.openPorts}
                                onChange={(e) => handleFilterChange('openPorts', e.target.value)}
                                list="portsSuggestions"
                            />
                            <datalist id="portsSuggestions">
                                {getSuggestions('openPorts').map((suggestion, index) => (
                                    <option key={index} value={suggestion} />
                                ))}
                            </datalist>
                        </th>
                        <th>
                            Tag
                            <input
                                type="text"
                                placeholder="Filter by Tag"
                                value={filterValues.tag}
                                onChange={(e) => handleFilterChange('tag', e.target.value)}
                                list="tagSuggestions"
                            />
                            <datalist id="tagSuggestions">
                                {getSuggestions('tag').map((suggestion, index) => (
                                    <option key={index} value={suggestion} />
                                ))}
                            </datalist>
                        </th>
                        <th onClick={() => handleSort('createdAt')}>Create At {sortConfig.key === 'createdAt' && (sortConfig.direction === 'ascending' ? '↑' : sortConfig.direction === 'descending' ? '↓' : '')}</th>
                        <th>Last Update</th>
                        <th>DNS Type</th>
                        <th>DNS Content</th>
                        <th>DNS IP</th>
                        <th>DNS IN IPs</th>
                        <th>DNS Src Provider</th>
                        <th>Total Vulnerabilities</th>
                        <th>Total SubDomains</th>
                    </tr>
                </thead>
                <tbody>
                    {currentTargets.map(target => (
                        <tr key={target._id.$oid}>
                            <td>
                                <input
                                    type="checkbox"
                                    checked={selectedTargets.includes(target._id.$oid)}
                                    onChange={() => handleSelectTarget(target._id.$oid)}
                                />
                            </td>
                            <td>{target._id.$oid}</td>
                            <td contentEditable={selectedTargets.includes(target._id.$oid)}
                                suppressContentEditableWarning={true}
                                onBlur={(e) => handleEditTarget(target._id.$oid, 'domain', e.target.textContent)}
                            >
                                {target.domain}
                            </td>
                            <td contentEditable={selectedTargets.includes(target._id.$oid)}
                                suppressContentEditableWarning={true}
                                onBlur={(e) => handleEditTarget(target._id.$oid, 'rootDomain', e.target.textContent)}
                            >
                                {target.rootDomain}
                            </td>
                            <td>
                                {Array.isArray(target.ports) ? (
                                    target.ports.map((ports, index) => (
                                        <span key={index} className="tag-label">{ports}</span>
                                    ))
                                ) : (
                                    <span className="tag-label">{target.ports}</span>
                                )}
                            </td>
                            <td>
                                {selectedTargets.includes(target._id.$oid) ? (
                                    <textarea
                                        value={Array.isArray(editTargets[target._id.$oid]?.tag) ? editTargets[target._id.$oid].tag.join(', ') : target.tag.join(', ')}
                                        onChange={(e) => handleEditTarget(target._id.$oid, 'tag', e.target.value)}
                                    />
                                ) : (
                                    Array.isArray(target.tag) ? (
                                        target.tag.map((tag, index) => (
                                            <span key={index} className="tag-label">{tag}</span>
                                        ))
                                    ) : (
                                        <span className="tag-label">{target.tag}</span>
                                        )
                                )}
                            </td>

                            <td>
                                {new Date(target.createdAt.$date).toLocaleString("en-US", {
                                    year: 'numeric',
                                    month: '2-digit',
                                    day: '2-digit',
                                    hour: '2-digit',
                                    minute: '2-digit',
                                    second: '2-digit',
                                    hour12: false
                                })}
                            </td>
                            <td>
                                {new Date(target.lastUpdate.$date).toLocaleString("en-US", {
                                    year: 'numeric',
                                    month: '2-digit',
                                    day: '2-digit',
                                    hour: '2-digit',
                                    minute: '2-digit',
                                    second: '2-digit',
                                    hour12: false
                                })}
                            </td>
                            <td>{target.type}</td>
                            <td>{target.dns_content}</td>
                            <td>{target.ip}</td>
                            <td>{target.in_public_ips}</td>
                            <td>{target.source_provider}</td>
                            <td>{target.totalVulnerability}</td>
                            <td>{target.totalSubDomains}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
            
            <button 
                type="button" 
                onClick={handleSave} 
                disabled={Object.keys(editTargets).length === 0}>
                Save Changes
            </button>
            <div className="pagination">
                {renderPageNumbers()}
            </div>
        </div>
    );
};

export default ManageTargets;
