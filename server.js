const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Sequelize, DataTypes } = require('sequelize');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// إعدادات الأمان
app.use(helmet());
app.use(cors());
app.use(express.json());

// تحديد المعدل
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// إعداد قاعدة البيانات
const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  dialectOptions: {
    ssl: process.env.NODE_ENV === 'production' ? {
      require: true,
      rejectUnauthorized: false
    } : false
  }
});

// نموذج المستخدم البسيط
const User = sequelize.define('User', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false
  },
  firstName: {
    type: DataTypes.STRING,
    allowNull: false
  },
  lastName: {
    type: DataTypes.STRING,
    allowNull: false
  },
  role: {
    type: DataTypes.ENUM('admin', 'doctor', 'receptionist', 'patient'),
    defaultValue: 'patient'
  }
});

// نموذج المريض البسيط
const Patient = sequelize.define('Patient', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  patientId: {
    type: DataTypes.STRING,
    unique: true
  },
  phone: DataTypes.STRING,
  dateOfBirth: DataTypes.DATEONLY,
  address: DataTypes.TEXT
});

// العلاقات
User.hasOne(Patient, { foreignKey: 'userId' });
Patient.belongsTo(User, { foreignKey: 'userId' });

// المسارات الأساسية
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'نظام إدارة عيادة الأسنان يعمل بنجاح!',
    timestamp: new Date().toISOString()
  });
});

app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'الخادم يعمل بنجاح!',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development'
  });
});

// مسار تسجيل مستخدم جديد
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, firstName, lastName, role = 'patient' } = req.body;
    
    // تشفير كلمة المرور
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // إنشاء المستخدم
    const user = await User.create({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      role
    });

    // إنشاء ملف مريض إذا كان الدور مريض
    if (role === 'patient') {
      const patientCount = await Patient.count();
      await Patient.create({
        userId: user.id,
        patientId: `P${String(patientCount + 1).padStart(6, '0')}`
      });
    }

    res.status(201).json({
      message: 'تم إنشاء الحساب بنجاح',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role
      }
    });
  } catch (error) {
    res.status(400).json({ 
      message: 'خطأ في إنشاء الحساب',
      error: error.message 
    });
  }
});

// مسار تسجيل الدخول
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(401).json({ message: 'بيانات الدخول غير صحيحة' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'بيانات الدخول غير صحيحة' });
    }

    const token = jwt.sign(
      { userId: user.id, role: user.role },
      process.env.JWT_SECRET || 'dental_clinic_secret_key',
      { expiresIn: '7d' }
    );

    res.json({
      message: 'تم تسجيل الدخول بنجاح',
      token,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ 
      message: 'خطأ في الخادم',
      error: error.message 
    });
  }
});

// مسار الحصول على المستخدمين
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.findAll({
      attributes: ['id', 'email', 'firstName', 'lastName', 'role', 'createdAt']
    });
    res.json({ users });
  } catch (error) {
    res.status(500).json({ 
      message: 'خطأ في جلب المستخدمين',
      error: error.message 
    });
  }
});

// مسار معلومات النظام
app.get('/api/info', (req, res) => {
  res.json({
    name: 'نظام إدارة عيادة الأسنان',
    version: '1.0.0',
    description: 'نظام شامل لإدارة العيادات الطبية',
    features: [
      'إدارة المرضى',
      'جدولة المواعيد', 
      'متابعة العلاجات',
      'إدارة المدفوعات',
      'تقارير شاملة'
    ],
    status: 'نشط',
    lastUpdate: new Date().toISOString()
  });
});

// معالجة الأخطاء
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    message: 'حدث خطأ في الخادم',
    error: process.env.NODE_ENV === 'production' ? 'خطأ داخلي' : err.message
  });
});

// مسار افتراضي
app.get('/', (req, res) => {
  res.json({
    message: 'مرحباً بك في نظام إدارة عيادة الأسنان! 🦷',
    apiEndpoints: {
      health: '/api/health',
      test: '/api/test',
      register: 'POST /api/register',
      login: 'POST /api/login',
      users: '/api/users',
      info: '/api/info'
    }
  });
});

const PORT = process.env.PORT || 5000;

// تشغيل الخادم
const startServer = async () => {
  try {
    await sequelize.authenticate();
    console.log('✅ تم الاتصال بقاعدة البيانات بنجاح');
    
    await sequelize.sync();
    console.log('✅ تم تزامن قاعدة البيانات بنجاح');

    // إنشاء مستخدم مدير افتراضي
    const adminExists = await User.findOne({ where: { email: 'admin@clinic.com' } });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await User.create({
        email: 'admin@clinic.com',
        password: hashedPassword,
        firstName: 'مدير',
        lastName: 'النظام',
        role: 'admin'
      });
      console.log('✅ تم إنشاء حساب المدير الافتراضي');
    }
    
    app.listen(PORT, () => {
      console.log(`🚀 الخادم يعمل على البورت ${PORT}`);
      console.log(`🌍 البيئة: ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (error) {
    console.error('❌ خطأ في تشغيل الخادم:', error);
    process.exit(1);
  }
};

startServer();
