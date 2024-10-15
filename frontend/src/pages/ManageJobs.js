import React, { useState, useEffect } from 'react';
import axiosInstance from '../components/axiosConfig';
import '../css/components/ManageJobs.css';

const ManageJobs = () => {
    const [jobs, setJobs] = useState([]);
    const [currentPage, setCurrentPage] = useState(1);
    const [itemsPerPage, setItemsPerPage] = useState(10);
    const [searchKeyword, setSearchKeyword] = useState('');
    const [selectedJobs, setSelectedJobs] = useState([]);

    useEffect(() => {
        fetchJobs();
    }, []);

    const handleSearch = async (e) => {
        e.preventDefault();
        try {
            const response = await axiosInstance.get(`/api/jobs/search?keyword=${searchKeyword}`);
            setJobs(response.data);
        } catch (error) {
            console.error("Failed to search jobs", error);
        }
    };

    const handleSelectJob = (jobId) => {
        setSelectedJobs(prevState =>
            prevState.includes(jobId)
                ? prevState.filter(id => id !== jobId)
                : [...prevState, jobId]
        );
    };

    const handleSelectAllJobs = () => {
        if (selectedJobs.length === jobs.length) {
            setSelectedJobs([]);
        } else {
            setSelectedJobs(jobs.map(job => job._id.$oid));
        }
    };

    const handleDeleteJobs = async () => {
        try {
            await axiosInstance.post('/api/jobs/delete', { jobs: selectedJobs });
            fetchJobs(); // Refresh the job list
            setSelectedJobs([]);
        } catch (error) {
            console.error("Failed to delete jobs", error);
        }
    };

    const fetchJobs = async () => {
        try {
            const response = await axiosInstance.get('/api/jobs');
            setJobs(response.data);
        } catch (error) {
            console.error("Failed to fetch jobs", error);
        }
    };

    const handleItemsPerPageChange = (e) => {
        setItemsPerPage(Number(e.target.value));
        setCurrentPage(1); // Reset to first page on items per page change
    };

    const totalPages = Math.ceil(jobs.length / itemsPerPage);

    const currentJobs = jobs.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

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
            <h2>Jobs Management</h2>
            <form onSubmit={handleSearch} className="search-form">
                <input
                    type="text"
                    placeholder="Search..."
                    value={searchKeyword}
                    onChange={(e) => setSearchKeyword(e.target.value)}
                />
                <button type="submit">Search</button>
                <button type="button" onClick={handleDeleteJobs} disabled={selectedJobs.length === 0}>
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
                    Total : {jobs.length}
                </label>
            </div>
            <table className="jobs-table">
                <thead>
                    <tr>
                        <th>
                            <input
                                type="checkbox"
                                checked={selectedJobs.length === jobs.length}
                                onChange={handleSelectAllJobs}
                            />
                        </th>
                        <th>ID</th>
                        <th>Type Job</th>
                        <th>Status</th>
                        <th>Tag</th>
                        <th>Target</th>
                        <th>Create At</th>
                        <th>Total Finding</th>
                    </tr>
                </thead>
                <tbody>
                    {currentJobs.map(job => {
                        let statusColor = '';
                        switch (job.status.toLowerCase()) {
                            case 'running':
                                statusColor = 'brown';
                                break;
                            
                            case 'done':
                                statusColor = 'green';
                                break;
                            default:
                                statusColor = '';
                        }
                        
                        return (
                            <tr key={job._id.$oid}>
                                <td>
                                    <input
                                        type="checkbox"
                                        checked={selectedJobs.includes(job._id.$oid)}
                                        onChange={() => handleSelectJob(job._id.$oid)}
                                    />
                                </td>
                                <td>{job._id.$oid}</td>
                                <td>{job.typeJob}</td>
                                <td>
                                        {/* Display status with color */}
                                        <span className="tag-label" style={{ color: statusColor }}>{job.status}</span>
                                    </td>
                                <td>{Array.isArray(job.tag) ? job.tag.join(', ') : job.tag}</td>
                                <td>{job.target}</td>
                                <td>
                                    {new Date(job.createdAt.$date).toLocaleString("en-US", {
                                        year: 'numeric',
                                        month: '2-digit',
                                        day: '2-digit',
                                        hour: '2-digit',
                                        minute: '2-digit',
                                        second: '2-digit',
                                        hour12: false
                                    })}
                                </td>
                                <td>{job.totalFinding}</td>
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

export default ManageJobs;
