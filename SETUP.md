# Setup Guide

## Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL 14+
- Docker & Docker Compose (optional)

## Quick Setup

### Automated Setup (Unix/Linux/Mac)

```bash
chmod +x setup.sh
./setup.sh
```

### Manual Setup

#### 1. Database Setup

```bash
# Install PostgreSQL (if not already installed)
# Ubuntu/Debian
sudo apt-get install postgresql postgresql-contrib

# macOS
brew install postgresql

# Start PostgreSQL
sudo service postgresql start  # Linux
brew services start postgresql # macOS

# Create database
sudo -u postgres psql
CREATE DATABASE url_attack_detector;
CREATE USER urldetector WITH PASSWORD 'urldetector123';
GRANT ALL PRIVILEGES ON DATABASE url_attack_detector TO urldetector;
\q
```

#### 2. Backend Setup

```bash
cd backend

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # Unix/Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Setup environment
cp .env.example .env
# Edit .env with your database credentials

# Create data directories
mkdir -p data/datasets data/models data/pcaps

# Generate dataset (15,000 samples)
python scripts/generate_dataset.py

# Train ML models (takes 5-10 minutes)
python scripts/train_model.py

# Start backend server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### 3. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Create environment file
echo "VITE_API_URL=http://localhost:8000" > .env

# Start development server
npm run dev
```

## Docker Setup

```bash
# Start all services
docker-compose up -d

# Generate dataset inside container
docker-compose exec backend python scripts/generate_dataset.py

# Train models inside container
docker-compose exec backend python scripts/train_model.py

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Verification

### Test Backend

```bash
# Health check
curl http://localhost:8000/health

# Test URL analysis
curl -X POST http://localhost:8000/api/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://example.com/page?id=1'"'"' OR '"'"'1'"'"'='"'"'1"}'
```

### Test Frontend

1. Open http://localhost:3000
2. Navigate to "Analyze URL"
3. Test with example URLs
4. Check Dashboard for statistics

## Troubleshooting

### Backend Issues

**Database connection error:**
- Verify PostgreSQL is running
- Check DATABASE_URL in .env
- Ensure database exists

**Module import errors:**
- Ensure virtual environment is activated
- Reinstall requirements: `pip install -r requirements.txt`

**PCAP parsing errors:**
- Install system dependencies:
  ```bash
  # Ubuntu/Debian
  sudo apt-get install tcpdump libpcap-dev

  # macOS
  brew install libpcap
  ```

### Frontend Issues

**Port already in use:**
- Change port in vite.config.ts
- Or kill process using port 3000

**API connection error:**
- Verify backend is running on port 8000
- Check VITE_API_URL in .env
- Check CORS settings in backend

### Docker Issues

**Container fails to start:**
- Check Docker logs: `docker-compose logs backend`
- Verify ports are not in use
- Ensure Docker has enough resources

**Database connection issues:**
- Wait for PostgreSQL to fully start (healthcheck)
- Check container logs: `docker-compose logs postgres`

## Next Steps

After successful setup:

1. **Generate Dataset**: Already done during setup
2. **Train Models**: Already done during setup
3. **Test Application**:
   - Visit http://localhost:3000
   - Try analyzing URLs
   - Upload PCAP files
   - Explore the dashboard
4. **Review API Docs**: Visit http://localhost:8000/docs

## Production Deployment

See [README.md](README.md#-production-deployment) for production deployment guidelines.
