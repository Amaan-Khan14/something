#!/bin/bash

# URL Attack Detector - Setup Script
# This script sets up the entire project from scratch

set -e

echo "========================================"
echo "URL Attack Detector - Setup Script"
echo "========================================"
echo ""

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.11 or higher."
    exit 1
fi
echo "✅ Python 3 found"

if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18 or higher."
    exit 1
fi
echo "✅ Node.js found"

if ! command -v docker &> /dev/null; then
    echo "⚠️  Docker is not installed. Docker deployment will not be available."
else
    echo "✅ Docker found"
fi

echo ""
echo "========================================"
echo "Setting up Backend"
echo "========================================"

# Backend setup
cd backend

echo "Creating Python virtual environment..."
python3 -m venv venv

echo "Activating virtual environment..."
source venv/bin/activate || . venv/Scripts/activate

echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "Creating environment file..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "✅ Created .env file. Please edit it with your configuration."
else
    echo "ℹ️  .env file already exists"
fi

echo "Creating data directories..."
mkdir -p data/datasets data/models data/pcaps

echo ""
echo "Generating synthetic dataset..."
python scripts/generate_dataset.py

echo ""
echo "Training ML models..."
python scripts/train_model.py

cd ..

echo ""
echo "========================================"
echo "Setting up Frontend"
echo "========================================"

cd frontend

echo "Installing npm dependencies..."
npm install

echo "Creating frontend environment file..."
if [ ! -f .env ]; then
    echo "VITE_API_URL=http://localhost:8000" > .env
    echo "✅ Created frontend .env file"
else
    echo "ℹ️  Frontend .env file already exists"
fi

cd ..

echo ""
echo "========================================"
echo "Setup Complete!"
echo "========================================"
echo ""
echo "To start the application:"
echo ""
echo "Option 1: Using Docker (Recommended)"
echo "  docker-compose up -d"
echo ""
echo "Option 2: Manual start"
echo "  Terminal 1 (Backend):"
echo "    cd backend"
echo "    source venv/bin/activate"
echo "    uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"
echo ""
echo "  Terminal 2 (Frontend):"
echo "    cd frontend"
echo "    npm run dev"
echo ""
echo "Access the application:"
echo "  Frontend: http://localhost:3000"
echo "  Backend API: http://localhost:8000"
echo "  API Docs: http://localhost:8000/docs"
echo ""
echo "========================================"
