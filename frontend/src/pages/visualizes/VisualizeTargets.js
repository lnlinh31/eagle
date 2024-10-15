import React, { useState, useEffect } from 'react';
import axiosInstance from '../../components/axiosConfig';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar
} from 'recharts';

const VisualizeTargets = () => {
  const [targets, setTargets] = useState([]);

  useEffect(() => {
    const fetchTargets = async () => {
      try {
        const response = await axiosInstance.get('/api/targets');
        setTargets(response.data);
      } catch (error) {
        console.error("Failed to fetch targets", error);
      }
    };

    fetchTargets();
  }, []);

  // Prepare data for line chart
  const chartData = targets.map(target => ({
    domain: target.domain,
    vulnerabilities: target.totalVulnerability,
    subdomains: target.totalSubDomains,
  }));

  // Preapare data for fan chart
  const openPortsFrequency = {};
  targets.forEach(target => {
    if (Array.isArray(target.ports)) {
      target.ports.forEach(port => {
        openPortsFrequency[port] = (openPortsFrequency[port] || 0) + 1;
      });
    }
  });

  const pieData = Object.keys(openPortsFrequency).map(port => ({
    name: port,
    value: openPortsFrequency[port],
  }));

  // Calculate number of open ports
  const totalPorts = pieData.reduce((sum, port) => sum + port.value, 0);

  // top 20 open ports
  const topPortsData = [...pieData].sort((a, b) => b.value - a.value).slice(0, 20);

  // Color of fan chart
  const COLORS = [
    '#FF0000', '#DDA0DD', '#EE82EE', '#DA70D6', '#BA55D3', 
    '#9370DB', '#8A2BE2', '#7B68EE', '#6A5ACD', '#483D8B', 
    '#4169E1', '#4682B4', '#5F9EA0', '#66CDAA', '#7FFFD4', 
    '#AFEEEE', '#ADD8E6', '#87CEFA', '#87CEEB', '#00BFFF'
  ];
  return (
    <div>
      <h2>Visualize Targets</h2>
      <ResponsiveContainer width="100%" height={400}>
        <LineChart
          data={chartData}
          margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
        >
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="domain" />
          <YAxis />
          <Tooltip />
          <Legend />
          <Line type="monotone" dataKey="vulnerabilities" stroke="#8884d8" />
          <Line type="monotone" dataKey="subdomains" stroke="#82ca9d" />
        </LineChart>
      </ResponsiveContainer>

      <h3>Open Ports Distribution</h3>
      <ResponsiveContainer width="100%" height={400}>
        <PieChart>
          <Pie
            data={pieData}
            cx="50%"
            cy="50%"
            labelLine={false}
            label={({ name, value }) => `${name}: ${(value / totalPorts * 100).toFixed(2)}%`}
            outerRadius={150}
            fill="#8884d8"
            dataKey="value"
          >
            {pieData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip />
        </PieChart>
      </ResponsiveContainer>

      <h3>Top 20 Open Ports</h3>
      <ResponsiveContainer width="100%" height={400}>
        <BarChart data={topPortsData}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="name" />
          <YAxis />
          <Tooltip />
          <Legend />
          <Bar dataKey="value" fill="#8884d8" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

export default VisualizeTargets;