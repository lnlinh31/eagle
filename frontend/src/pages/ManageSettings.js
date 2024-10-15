import React, { useState } from 'react';
import axiosInstance from '../components/axiosConfig';

const ManageSettings = () => {
  const [channel, setChannel] = useState('');
  const [settings, setSettings] = useState({});
  const [message, setMessage] = useState('');
  
  const handleChannelChange = (event) => {
    setChannel(event.target.value);
    setSettings({});
  };

  const handleSave = async () => {
    try {
      const response = await axiosInstance.post('/api/settings/alert', { message, channel, settings }, {
      });
      alert(response.data.message);
    } catch (error) {
      alert('Error sending alert');
      console.error(error);
    }
  };

  const renderSettingsFields = () => {
    switch(channel) {
      case 'telegram':
        return (
          <>
            <div>
              <label>Chat ID:</label>
              <input
                type="text"
                value={settings.chat_id || ''}
                onChange={(e) => setSettings({ ...settings, chat_id: e.target.value })}
              />
            </div>
          </>
        );
      case 'slack':
        return (
          <>
            <div>
              <label>Webhook URL:</label>
              <input
                type="text"
                value={settings.webhook_url || ''}
                onChange={(e) => setSettings({ ...settings, webhook_url: e.target.value })}
              />
            </div>
          </>
        );
      case 'email':
        return (
          <>
            <div>
              <label>Email:</label>
              <input
                type="email"
                value={settings.email || ''}
                onChange={(e) => setSettings({ ...settings, email: e.target.value })}
              />
            </div>
          </>
        );
      default:
        return null;
    }
  };

  return (
    <div>
      <h1>Manage Alert Settings</h1>
      <div>
        <label>Select Channel:</label>
        <select value={channel} onChange={handleChannelChange}>
          <option value="">Select...</option>
          <option value="telegram">Telegram</option>
          <option value="slack">Slack</option>
          <option value="email">Email</option>
        </select>
      </div>
      {channel && (
        <div>
          {renderSettingsFields()}
        </div>
      )}
      <div>
        <label>Message:</label>
        <textarea
          value={message}
          onChange={(e) => setMessage(e.target.value)}
        />
      </div>
      <button onClick={handleSave}>Save</button>
    </div>
  );
};

export default ManageSettings;