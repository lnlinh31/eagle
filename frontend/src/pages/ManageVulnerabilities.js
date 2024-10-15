import React, { useState, useEffect } from 'react';
import axiosInstance from '../components/axiosConfig';
import '../css/components/ManageVulnerabilities.css'; 

const ManageVulnerabilities = () => {
    const [vulnerabilities, setVulnerabilities] = useState([]);
    const [searchKeyword, setSearchKeyword] = useState('');
    const [currentPage, setCurrentPage] = useState(1);
    const [itemsPerPage, setItemsPerPage] = useState(10);
    const [selectedVuls, setSelectedVuls] = useState([]);

    useEffect(() => {
        fetchVulnerabilities();
    }, []);

    const handleSearch = async (e) => {
        e.preventDefault();
        try {
            const response = await axiosInstance.get(`/api/vulnerabilities/search?keyword=${searchKeyword}`);
            setVulnerabilities(response.data);
        } catch (error) {
            console.error("Failed to search vulnerabilities", error);
        }
    };

    const handleSelectVul = (vulId) => {
        setSelectedVuls(prevState =>
            prevState.includes(vulId)
                ? prevState.filter(id => id !== vulId)
                : [...prevState, vulId]
        );
    };

    const handleSelectAllVuls = () => {
        if (selectedVuls.length === vulnerabilities.length) {
            setSelectedVuls([]);
        } else {
            setSelectedVuls(vulnerabilities.map(vul => vul._id.$oid));
        }
    };

    const handleDeleteVulnerabilitiess = async () => {
        try {
            await axiosInstance.post('/api/vulnerabilities/delete', { vulnerabilities: selectedVuls });
            fetchVulnerabilities(); // Refresh the job list
            setSelectedVuls([]);
        } catch (error) {
            console.error("Failed to delete jobs", error);
        }
    };

    const fetchVulnerabilities = async () => {
        try {
            const response = await axiosInstance.get('/api/vulnerabilities');
            setVulnerabilities(response.data);
        } catch (error) {
            console.error("Failed to fetch vulnerabilities", error);
        }
    };

    const handleItemsPerPageChange = (e) => {
        setItemsPerPage(Number(e.target.value));
        setCurrentPage(1); // Reset to first page on items per page change
    };

    const totalPages = Math.ceil(vulnerabilities.length / itemsPerPage);

    const currentVulnerabilitiess = vulnerabilities.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

    const renderPageNumbers = () => {
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

        if (startPage > 1) {
            pageNumbers.unshift(<span key="start-ellipsis">...</span>);
            pageNumbers.unshift(
                <button key={1} onClick={() => setCurrentPage(1)}>
                    1
                </button>
            );
        }

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

    return (
        <div>
            <h2>Vulnerabilities Management</h2>
            <form onSubmit={handleSearch} className="search-form">
                <input
                    type="text"
                    placeholder="Search..."
                    value={searchKeyword}
                    onChange={(e) => setSearchKeyword(e.target.value)}
                />
                <button type="submit">Search</button>
                <button type="button" onClick={handleDeleteVulnerabilitiess} disabled={selectedVuls.length === 0}>
                    Delete
                </button>
            </form>
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
                    Total : {vulnerabilities.length}
                </label>
            </div>
            <table className="vulnerabilities-table">
                <thead>
                    <tr>
                        <th>
                            <input
                                type="checkbox"
                                checked={selectedVuls.length === vulnerabilities.length}
                                onChange={handleSelectAllVuls}
                            />
                        </th>
                        <th>ID</th>
                        <th>TemplateID</th>
                        <th>Severity</th>
                        <th>Affected Item</th>
                        <th>Domain</th>
                        <th>Tag</th>
                        <th>Create At</th>
                    </tr>
                </thead>
                <tbody>
                    {currentVulnerabilitiess.map(vul => {
                        // Determine the color based on the severity level
                        let severityColor = '';
                        switch (vul.severity.toLowerCase()) {
                            case 'critical':
                                severityColor = 'purple';
                                break;
                            case 'high':
                                severityColor = 'red';
                                break;
                            case 'medium':
                                severityColor = 'orange';
                                break;
                            case 'low':
                                severityColor = 'green';
                                break;
                            case 'info':
                                severityColor = 'blue';
                                break;
                            default:
                                severityColor = '';
                        }

                        return (
                            <tr key={vul._id.$oid}>
                                <td>
                                    <input
                                        type="checkbox"
                                        checked={selectedVuls.includes(vul._id.$oid)}
                                        onChange={() => handleSelectVul(vul._id.$oid)}
                                    />
                                </td>
                                <td>{vul._id.$oid}</td>
                                <td>{vul.id}</td>
                                <td>
                                    {/* Display severity with color */}
                                    <span className="tag-label" style={{ color: severityColor }}>{vul.severity}</span>
                                </td>
                                <td>{vul.affectedItem}</td>
                                <td>{vul.domain}</td>
                                <td>
                                    {selectedVuls.includes(vul._id.$oid) ? null : (
                                        Array.isArray(vul.tag) ? (
                                            vul.tag.map((tag, index) => (
                                            <span key={index} className="tag-label">{tag}</span>
                                        ))
                                        ) : (
                                        <span className="tag-label">{vul.tag || "No tags available"}</span>
                                        )
                                    )}
                                </td>

                                <td>
                                    {new Date(vul.createdAt.$date).toLocaleString("en-US", {
                                        year: 'numeric',
                                        month: '2-digit',
                                        day: '2-digit',
                                        hour: '2-digit',
                                        minute: '2-digit',
                                        second: '2-digit',
                                        hour12: false
                                    })}
                                </td>
                            </tr>
                        );
                    })}
                </tbody>


            </table>
            <div className="pagination">
                {renderPageNumbers()}
            </div>
        </div>
    );
};

export default ManageVulnerabilities;
