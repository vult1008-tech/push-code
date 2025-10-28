from app import app

if __name__ == '__main__':
    print("🚀 Starting Online Class Manager...")
    print("📍 Access the application at: http://localhost:5000")
    print("👨‍🏫 Demo Teacher: teacher1 / password123")
    print("👨‍🎓 Demo Students: student1, student2, student3, student4, student5 / password123")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)