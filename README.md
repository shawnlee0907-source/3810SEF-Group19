# COMP3810SEF GROUP PROJECT

## Project Overview
**Flight Dashboard** - A comprehensive Flight Management System built with Node.js that allows users to manage flight information with full CRUD operations and user authentication.

## Team Members
1. Lee Sheung Lam (14022297)
2. Li Kam Yeung (14011314)
3. Chan Long Hin (14078011)
4. Mo Yuen Yi (13175765)
5. Miao Qin Yin (13218978)

## System Architecture

### Core Features
- **User Authentication**: Secure registration and login system
- **Flight Management**: Complete CRUD operations for flight data
- **Search & Filter**: Advanced search functionality
- **File Upload**: Support for flight photos
- **RESTful API**: Full API integration
- **User Isolation**: Data separation between users

### Technical Stack
- **Backend**: Express.js with EJS templating
- **Database**: MongoDB with native driver
- **Authentication**: bcrypt hashing + express-session
- **File Handling**: express-formidable for uploads
- **HTTP Methods**: method-override for PUT/DELETE

## Project Structure

### Key Dependencies
```json
{
  "express": "^4.19.2",
  "ejs": "^3.1.10",
  "mongodb": "^6.8.0",
  "bcrypt": "^5.1.1",
  "express-session": "^1.18.0",
  "express-formidable": "^1.2.0",
  "method-override": "^3.0.0"
}
```

### Directory Structure
```
├── public/          # Static assets (CSS, images, JS)
├── views/           # EJS templates
│   ├── api-test.ejs
│   ├── create.ejs
│   ├── details.ejs
│   ├── edit.ejs
│   ├── info.ejs
│   ├── list.ejs
│   ├── login.ejs
│   └── register.ejs
└── app.js          # Main application file
```

## Application URLs

### Live Deployment
**Cloud Server**: https://comp3810sef-group19-vubv.onrender.com/login

### Route Endpoints
- **Authentication**: `/login`, `/register`, `/logout`
- **Flight Management**: `/list`, `/details`, `/edit`, `/create`
- **API Interface**: `/api-test`
- **REST API**: `/api/flights`

## User Guide

### 1. Authentication
**Demo Account**: 
- Username: `4321`
- Password: `4321`

### 2. Flight Dashboard
After login, users can:
- View all their flights
- Search flights by various criteria
- Access detailed flight information

### 3. Flight Operations

#### Create Flight
- Navigate to "Add New Flight"
- Fill in flight details
- Optional photo upload
- Submit to create new flight

#### Read/View Flights
- View flight list on main dashboard
- Use search functionality
- Click "Details" for comprehensive view

#### Update Flight
- Access via "Edit" button or flight details page
- Modify flight information
- Update changes

#### Delete Flight
- Use "Delete" button
- Confirm removal
- Flight is permanently deleted

### 4. Search Functionality
- Search by: Flight number, destination, airline, airports
- Real-time filtering
- Multiple search criteria

### 5. Session Management
- Secure logout functionality
- Session-based authentication
- Automatic redirect to login when session expires

## RESTful API Usage

The system provides a complete REST API at `/api/flights` with the following endpoints:

### Authentication Required
All API requests require valid session authentication.

### API Endpoints

#### 1. Login (Create Session)
```bash
curl -c cookie.txt -X POST https://comp3810sef-group19-vubv.onrender.com/login \
     -F "username=4321" \
     -F "password=4321"
```

#### 2. Read All Flights
```bash
curl -b cookie.txt https://comp3810sef-group19-vubv.onrender.com/api/flights
```

#### 3. Read Specific Flight
```bash
curl -b cookie.txt https://comp3810sef-group19-vubv.onrender.com/api/flights/FLIGHT_NUMBER
```

#### 4. Create Flight
```bash
curl -b cookie.txt -X POST https://comp3810sef-group19-vubv.onrender.com/api/flights \
     -F "flightNumber=CX225" \
     -F "airline=Cathay Pacific" \
     -F "departureAirport=HKG" \
     -F "arrivalAirport=NRT"
```

#### 5. Update Flight
```bash
curl -b cookie.txt -X PUT https://comp3810sef-group19-vubv.onrender.com/api/flights/CX225 \
     -F "status=Delayed" \
     -F "gate=71A"
```

#### 6. Delete Flight
```bash
curl -b cookie.txt -X DELETE https://comp3810sef-group19-vubv.onrender.com/api/flights/CX225
```

## Security Features

- Password hashing with bcrypt
- Session-based authentication
- User data isolation
- Protected routes middleware
- Secure file upload handling

## Data Management

- Each user only sees their own flights
- MongoDB document-based storage
- Base64 image encoding for flight photos
- Automatic sorting by creation date (newest first)

## Development Features

- MVC-like architecture
- RESTful API design
- Form data validation
- Error handling
- Responsive web interface

