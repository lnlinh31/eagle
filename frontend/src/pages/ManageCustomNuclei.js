import React, { useState, useEffect } from 'react';
import axiosInstance from '../components/axiosConfig';
import Autocomplete from '@mui/lab/Autocomplete'; 
import { TextField, Button, Dialog, DialogTitle, DialogContent, DialogActions, Tabs, Tab, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TableSortLabel } from '@mui/material'; 

const ManageCustomNuclei = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [templateName, setTemplateName] = useState('');
  const [templateContent, setTemplateContent] = useState('');
  const [customTemplates, setCustomTemplates] = useState([]);
  const [filteredTemplates, setFilteredTemplates] = useState([]);
  const [searchKeyword, setSearchKeyword] = useState('');
  const [selectedTemplate, setSelectedTemplate] = useState(null);
  const [tags, setTags] = useState([]);
  const [selectedTag, setSelectedTag] = useState(null);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [schedule, setSchedule] = useState({ hour: '', day: '', month: '' });
  const [filteredTags, setFilteredTags] = useState([]);

  useEffect(() => {
    fetchTemplates();
    fetchTags();
  }, []);

  useEffect(() => {
    filterTemplates(searchKeyword);
  }, [searchKeyword, customTemplates]);

  const fetchTemplates = () => {
    axiosInstance.get('/api/customnuclei/templates') // Call API for get templates
      .then(response => setCustomTemplates(response.data))
      .catch(error => console.error(error));
  };

  const fetchTags = () => {
    axiosInstance.get('/api/targets/tags') // Call API for get all tags from targets
      .then(response => setTags(response.data))
      .catch(error => console.error(error));
  };

  const handleAddTemplate = () => {
    axiosInstance.post('/api/templates', { name: templateName, content: templateContent })
      .then(response => {
        alert('Template added successfully!');
        setTemplateName('');
        setTemplateContent('');
        fetchTemplates(); // Update list of templates
      })
      .catch(error => console.error(error));
  };

  const handleAddCustomScan = () => {
    axiosInstance.post('/api/customnuclei/custom-scan', {
      template: selectedTemplate,
      targetTag: selectedTag,
      schedule: schedule
    })
    .then(response => {
      alert('Custom scan job created successfully!');
      setWizardOpen(false);
    })
    .catch(error => console.error(error));
  };

  const handleSearchChange = (event) => {
    setSearchKeyword(event.target.value);
  };

  const filterTemplates = (keyword) => {
    const filtered = customTemplates.filter(template => 
      template.name.toLowerCase().includes(keyword.toLowerCase())
    );
    setFilteredTemplates(filtered);
  };

  // const handleScheduleChange = (field) => (event) => {
  //   setSchedule({ ...schedule, [field]: event.target.value });
  // };

  const handleTagInputChange = (event, value) => {
    if (value) {
      const filtered = tags.filter(tag => tag.toLowerCase().includes(value.toLowerCase()));
      setFilteredTags(filtered); // Update list of filter tag 
    } else {
      setFilteredTags(tags); // Show all tags when empty input
    }
  };

  
  const handleEditTemplate = (template) => {

    setTemplateName(template.name);
    setTemplateContent(template.content);
  
  };

  const handleDeleteTemplate = (templateId) => {
    axiosInstance.delete(`/api/templates/${templateId}`)
      .then(response => {
        alert('Template deleted successfully!');
        
        setCustomTemplates(customTemplates.filter(template => template.id !== templateId));
      })
      .catch(error => console.error(error));
  };


  return (
    <div>
      <Tabs value={activeTab} onChange={(event, newValue) => setActiveTab(newValue)} aria-label="tabs">
        <Tab label="Add New Nuclei Template" />
        <Tab label="Custom Nuclei Scan" />
      </Tabs>

      {activeTab === 0 && (
        <div>
          <h2>Add New Nuclei Template</h2>
          <TextField
            label="Template Name"
            value={templateName}
            onChange={e => setTemplateName(e.target.value)}
            fullWidth
          />
          <TextField
            label="Template Content"
            value={templateContent}
            onChange={e => setTemplateContent(e.target.value)}
            multiline
            rows={6}
            fullWidth
          />
          <Button variant="contained" color="primary" onClick={handleAddTemplate}>
            Save Template
          </Button>

          <hr />

          <TextField
            label="Search Templates"
            value={searchKeyword}
            onChange={handleSearchChange}
            fullWidth
          />
          
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Actions</TableCell>
                  <TableCell><TableSortLabel>Name</TableSortLabel></TableCell>
                  <TableCell>Content</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredTemplates.map((template) => (
                  <TableRow key={template.id}>
                    <TableCell>
                      <Button onClick={() => handleEditTemplate(template.id)}>Edit</Button>
                      <Button onClick={() => handleDeleteTemplate(template.id)}>Delete</Button>
                    </TableCell>
                    <TableCell>{template.name}</TableCell>
                    <TableCell>{template.content}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </div>
      )}

      {activeTab === 1 && (
        <div>
          <h2>Custom Nuclei Scan</h2>
          <Button variant="contained" color="secondary" onClick={() => setWizardOpen(true)}>
            Add Custom Scan
          </Button>

          <Dialog open={wizardOpen} onClose={() => setWizardOpen(false)} maxWidth="sm" fullWidth>
            <DialogTitle>Custom Nuclei Scan Wizard</DialogTitle>
            <DialogContent>
              {/* Autocomplete to pick template */}
              <Autocomplete
                options={customTemplates}
                getOptionLabel={(option) => option.name}
                onChange={(event, newValue) => setSelectedTemplate(newValue)}
                renderInput={(params) => <TextField {...params} label="Pick Template" fullWidth />}
              />
              <br />
              {/* Autocomplete to pick target tag */}
              <Autocomplete
                options={filteredTags} // Sử dụng tags đã được lọc
                getOptionLabel={(option) => option}
                onInputChange={handleTagInputChange} // Lọc tag cục bộ khi input thay đổi
                onChange={(event, newValue) => setSelectedTag(newValue)}
                renderInput={(params) => <TextField {...params} label="Pick Target (Tag)" fullWidth />}
              />
              <br />
              {/* Scheduler for custom scan */}
              {/* <TextField
                label="Hour"
                value={schedule.hour}
                onChange={handleScheduleChange('hour')}
                fullWidth
              />
              <TextField
                label="Day of Week"
                value={schedule.day}
                onChange={handleScheduleChange('day')}
                fullWidth
              />
              <TextField
                label="Month"
                value={schedule.month}
                onChange={handleScheduleChange('month')}
                fullWidth
              /> */}
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setWizardOpen(false)} color="default">
                Cancel
              </Button>
              <Button onClick={handleAddCustomScan} color="primary">
                Save Custom Scan
              </Button>
            </DialogActions>
          </Dialog>
        </div>
      )}
    </div>
  );
};

export default ManageCustomNuclei;
