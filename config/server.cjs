const express = require('express');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const expressSession = require('express-session');  // Importamos express-session

const app = express();
const PORT = 3001;
const JWT_SECRET = '#HX!5612IeLPV#QKgBs5Smk663?!MDMkHqtwDQns';

app.use(cors({
    origin: 'http://localhost:4321',
    credentials: true
}));

app.use(express.json());
app.use(cookieParser());

// Configura express-session antes de inicializar passport
app.use(expressSession({
    secret: '38LZI21@&gJQfk!2v?8$6MUw84VW@bqZLGcJUJSw',
    resave: false,
    saveUninitialized: false, // Esto evitará que se guarde la sesión si no se ha inicializado (es decir, si no ha sido modificada).
    cookie: { secure: false }
}));

app.use(passport.initialize());
app.use(passport.session());  // Añade soporte de sesiones a passport

// Configuración de Passport para Google OAuth
passport.use(new GoogleStrategy({
    clientID: '530247183798-fgvm9fss4vktu2hk1u44fiorvnhm2ipg.apps.googleusercontent.com',
    clientSecret: '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',
    callbackURL: "http://localhost:3001/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    let userEmail = profile.emails[0].value;

    let existingUser = await User.findOne({ email: userEmail });

    if (existingUser) {
        // Si el usuario ya está registrado pero no con Google.
        if (!existingUser.googleAuth) {
            existingUser.googleAuth = true;
            await existingUser.save();
        }
    } else {
        // Registra al usuario con googleAuth como true.
        existingUser = new User({
            email: userEmail,
            googleAuth: true
            // Aquí puedes agregar más campos si es necesario
        });

        await existingUser.save();
    }

    return done(null, existingUser);
}));

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'], prompt: 'select_account' }));

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    async (req, res) => {
        let token = req.user.token;

        if (req.user.token && !req.user.tokenActive) {
            req.user.tokenActive = true;
            await req.user.save();
        } else if (!req.user.token) {
            token = jwt.sign({ userId: req.user._id }, JWT_SECRET);
            req.user.token = token;
            req.user.tokenActive = true;
            await req.user.save();
        }

        res.cookie('token', token, {
            httpOnly: true,
            secure: false,
            maxAge: 3600000
        });

        res.redirect('http://localhost:4321/');
    });

// Serialize y Deserialize para Passport
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

const mongoURL = "mongodb+srv://Willlowbi:sMXRYmbHAlaQuPCg@cluster0.nikwpfz.mongodb.net/LiloExpress";

mongoose.connect(mongoURL, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("Conectado a MongoDB"))
    .catch(err => console.error("Error conectando a MongoDB:", err));

const userSchema = new mongoose.Schema({
    genero: String,
    nombre: String,
    apellido: String,
    email: String,
    password: String,
    tipoDocumento: String,
    numeroIdentificacion: String,
    fechaNacimiento: Date,
    token: String,
    tokenActive: { type: Boolean, default: false }, // nuevo campo
    googleAuth: { type: Boolean, default: false }
});

const User = mongoose.model('User', userSchema, 'Users');

app.post('/register', async (req, res) => {
    const { email, numeroIdentificacion } = req.body;

    const existingUser = await User.findOne({
        $or: [{ email }, { numeroIdentificacion }]
    });

    if (existingUser) {
        if (existingUser.email === email) {
            return res.status(400).send('Usuario ya registrado con ese email.');
        }
        if (existingUser.numeroIdentificacion === numeroIdentificacion) {
            return res.status(400).send('Usuario ya registrado con ese número de identificación.');
        }
    }

    let hashedPassword;
    try {
        const salt = bcrypt.genSaltSync(10);
        hashedPassword = bcrypt.hashSync(req.body.password, salt);
    } catch (error) {
        console.error("Error hashing password:", error);
        return res.status(500).send('Error hashing password.');
    }

    const newUser = new User({
        ...req.body,
        password: hashedPassword
    });

    try {
        await newUser.save();
        res.status(200).send('User registered!');
    } catch (err) {
        console.error("Error saving user:", err);
        res.status(500).send('Error registrando al usuario.');
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
        return res.status(401).send('El correo electrónico no está registrado.');
    }

    // Comprobar si el usuario ha sido registrado con Google OAuth y no tiene contraseña
    if (user.googleAuth && !user.password) {
        return res.status(401).send('Por favor inicie sesión con Google');
    }

    // Si el usuario tiene googleAuth como true pero también tiene una contraseña, permitimos que inicie sesión con contraseña
    if (user.password) {
        const validPassword = bcrypt.compareSync(password, user.password);
        if (!validPassword) {
            return res.status(401).send('Contraseña incorrecta.');
        }
    }

    let token = user.token;

    if (user.token && !user.tokenActive) {
        user.tokenActive = true;
        await user.save();
    } else if (!user.token) {
        token = jwt.sign({ userId: user._id }, JWT_SECRET);
        user.token = token;
        user.tokenActive = true;
        await user.save();
    }

    res.cookie('token', token, {
        httpOnly: true,
        secure: false,
        maxAge: 3600000
    });

    res.status(200).send('Inicio de sesión exitoso.');
});

app.get('/isAuthenticated', async (req, res) => {
    const token = req.cookies ? req.cookies.token : null;

    if (!token) {
        return res.json({ isAuthenticated: false });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId);

        if (user && user.tokenActive) {
            return res.json({ isAuthenticated: true });
        } else {
            return res.json({ isAuthenticated: false });
        }
    } catch {
        return res.json({ isAuthenticated: false });
    }
});

app.get('/user', async (req, res) => {
    const token = req.cookies ? req.cookies.token : null;

    if (!token) {
        return res.status(401).send('No estás autenticado.');
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId);

        if (user && user.tokenActive) {
            res.json({
                genero: user.genero,
                nombre: user.nombre,
                apellido: user.apellido,
                email: user.email,
                numeroIdentificacion: user.numeroIdentificacion,
            });
        } else {
            res.status(401).send('No estás autenticado.');
        }
    } catch {
        res.status(500).send('Hubo un error al procesar tu solicitud.');
    }
});

app.post('/user/update', async (req, res) => {
    const { genero, nombre, apellido, email, numeroIdentificacion } = req.body;

    // VALIDACIÓN: Número de Identificación
    if (!/^\d{10}$/.test(numeroIdentificacion)) {
        return res.status(400).send('Número de identificación inválido. Debe contener exactamente 10 dígitos.');
    }

    // VALIDACIÓN: Título Social
    if (genero.toLowerCase() !== 'hombre' && genero.toLowerCase() !== 'mujer') {
        return res.status(400).send('El género debe ser "hombre" o "mujer".');
    }

    // VALIDACIÓN: Email
    const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
    if (!emailRegex.test(email)) {
        return res.status(400).send('Email inválido.');
    }

    // Validar que no falte información requerida
    if (!genero || !nombre || !apellido || !email || !numeroIdentificacion) {
        return res.status(400).send('Faltan campos requeridos.');
    }

    // Obtener el token del usuario de las cookies
    const token = req.cookies ? req.cookies.token : null;

    if (!token) {
        return res.status(401).send('No estás autenticado.');
    }

    try {
        // Verificar el token y obtener el ID del usuario
        const decoded = jwt.verify(token, JWT_SECRET);

        // Buscar el usuario en la base de datos y actualizar su información
        const user = await User.findById(decoded.userId);
        if (!user) {
            return res.status(404).send('Usuario no encontrado.');
        }

        // Actualizar y guardar la nueva información del usuario
        user.genero = genero;
        user.nombre = nombre;
        user.apellido = apellido;
        user.email = email;
        user.numeroIdentificacion = numeroIdentificacion;
        await user.save();

        res.send('Actualización exitosa.');
    } catch (error) {
        console.error("Error al actualizar el usuario:", error);
        res.status(500).send('Hubo un problema al actualizar la información.');
    }
});

app.get('/logout', async (req, res) => {
    const token = req.cookies ? req.cookies.token : null;
    if (token) {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId);
        if (user) {
            user.tokenActive = false;
            await user.save();
        }
    }

    res.clearCookie('connect.sid');
    res.clearCookie('token');
    res.status(200).send('Sesión cerrada exitosamente.');
});

app.use(async (req, res, next) => {
    const token = req.cookies ? req.cookies.token : null;
    if (token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            const user = await User.findById(decoded.userId);
            if (user && user.tokenActive) {
                const currentTime = Math.floor(Date.now() / 1000); // obtener el tiempo actual en segundos
                const tokenIssuedAt = decoded.iat; // obtener el tiempo de emisión del token (iat = issued at)

                if (currentTime - tokenIssuedAt >= 3600) { // 3600 segundos = 1 hora
                    await logoutUser(req, res); // función para cerrar sesión
                } else {
                    next(); // continuar con el siguiente middleware o ruta
                }
            } else {
                next();
            }
        } catch (err) {
            next();
        }
    } else {
        next();
    }
});

async function logoutUser(req, res) {
    const token = req.cookies ? req.cookies.token : null;
    if (token) {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId);
        if (user) {
            user.tokenActive = false;
            await user.save();
        }
    }
    res.clearCookie('connect.sid');
    res.clearCookie('token');
    res.status(200).send('Sesión cerrada debido a la inactividad.');
}

const stock = {
    'Camiseta de Cuello Redondo Regular': {
        'negro': {
            'XS': 10,
            'S': 25,
            'M': 45,
            'L': 35,
            'XL': 25,
            'XXL': 10
        },
        'azul': {
            'XS': 8,
            'S': 20,
            'M': 40,
            'L': 30,
            'XL': 15,
            'XXL': 7
        },
        'verde': {
            'XS': 5,
            'S': 15,
            'M': 30,
            'L': 20,
            'XL': 15,
            'XXL': 5
        },
    },
    'Camiseta Oversize': {
        'verde': {
            'S': 28,
            'M': 77,
            'L': 91
        },
        'púrpura': {
            'S': 29,
            'M': 30,
            'L': 42
        },
        'negro': {
            'S': 16,
            'M': 16,
            'L': 42
        }
    },
    'Camisa Guayabera Cubana': {
        'blanco': {
            'S': 22,
            'M': 26,
            'L': 38,
            'XL': 32,
            'XXL': 59
        },
        'beige': {
            'S': 12,
            'M': 7,
            'L': 2,
            'XL': 20,
            'XXL': 135
        },
        'azul': {
            'S': 17,
            'M': 6,
            'L': 52,
            'XL': 44,
            'XXL': 75
        }
    },
    'Camisa Manga Corta Estampada Casual': {
        'blanco': {
            'XS': 20,
            'S': 9,
            'M': 18,
            'L': 9,
            'XL': 50
        }
    },
    'Jeans Clásico de Corte Holgado': {
        'azul': {
            '30': 2,
            '32': 6,
            '34': 15,
            '36': 2,
            '38': 37
        }
    },
    'Jeans Skinny sin Rotos': {
        'azul': {
            '28': 6,
            '30': 4,
            '32': 13,
            '34': 37
        }
    },
    'Pantalones Elásticos y Ajustados': {
        'negro': {
            '32': 2,
            '34': 3,
            '36': 2,
            '38': 4
        },
        'café': {
            '32': 6,
            '34': 4,
            '36': 10,
            '38': 6
        },
        'gris': {
            '32': 8,
            '34': 4,
            '36': 2,
            '38': 44
        }
    },
    'Pantalón Cargo': {
        'café': {
            '28': 36,
            '30': 15,
            '32': 44,
            '34': 58
        },
        'gris': {
            '28': 24,
            '30': 5,
            '32': 9,
            '34': 110
        },
        'beige': {
            '28': 3,
            '30': 2,
            '32': 2,
            '34': 5
        }
    },
    'Bermuda Slim en Jean': {
        'azul': {
            '28': 5,
            '30': 9,
            '32': 9
        }
    },
    'Bermuda en Drill Unicolor': {
        'azul': {
            '28': 9,
            '30': 2,
            '32': 42
        }
    },
    'Short Playero con Estampado': {
        'azul': {
            '28': 11,
            '30': 4,
            '32': 25
        }
    },
    'Short Piscinero con Estampado': {
        'gris': {
            '28': 8,
            '30': 34,
            '32': 93
        }
    }
};

app.get('/stock/:productName/:color/:size?', (req, res) => {
    const { productName, color, size } = req.params;

    const productStock = stock[productName];
    if (!productStock) {
        return res.status(404).send('Producto no encontrado');
    }

    const colorStock = productStock[color];
    if (!colorStock) {
        return res.status(404).send('Color no encontrado');
    }

    if (size) {
        const sizeStock = colorStock[size];
        if (sizeStock === undefined) {
            return res.status(404).send('Talla no encontrada');
        }
        res.json({ stock: sizeStock });
    } else {
        // Calcula el stock total para el color si no se proporciona la talla
        const totalStock = Object.values(colorStock).reduce((sum, quantity) => sum + quantity, 0);
        res.json({ totalStock: totalStock });
    }
});

function filterProductsByColor(ids, colors) {
    return ids.filter(id => {
        const productStock = stock[id];
        if (!productStock) return false;

        // Comprueba si el producto tiene alguno de los colores seleccionados
        return colors.some(color => productStock[color]);
    });
}

app.post('/filter/color', (req, res) => {
    const { ids, colors } = req.body;

    const filteredIds = filterProductsByColor(ids, colors);
    res.json(filteredIds);
});

function filterByMultipleSizes(ids, sizes) {
    return ids.filter(id => {
        const productStock = stock[id];
        if (!productStock) return false;

        // Comprueba si el producto tiene al menos una de las tallas seleccionadas en algún color
        return sizes.some(size =>
            Object.values(productStock).some(colorStock => colorStock.hasOwnProperty(size))
        );
    });
}

app.post('/filter/size', (req, res) => {
    const { ids, sizes } = req.body;
    const filteredIds = filterByMultipleSizes(ids, sizes);
    res.json(filteredIds);
});

// Definir el esquema para los productos
const productSchema = new mongoose.Schema({
    categoria: String,
    tipo: String,
    nombre: String,
    detalles: {
        tipoPrenda: String,
        color: String,
        talla: String,
        precio: Number,
        imagen: String,
        link: String
    },
    cantidad: {
        type: Number,
        default: 1
    }
});

const productImages = {
    'Camiseta de Cuello Redondo Regular': {
        'negro': {
            url: '/images/Hombres/Camisetas/Cuello Redondo/Negro/Camiseta-Cuello-Redondo-Negra-Cart.jpg',
            link: '/Hombre/Camisetas/Camiseta-Cuello-Redondo-Regular'
        },
        'azul': {
            url: '/images/Hombres/Camisetas/Cuello Redondo/Azul/Camiseta-Cuello-Redondo-Azul-Cart.jpg',
            link: '/Hombre/Camisetas/Camiseta-Cuello-Redondo-Regular'
        },
        'verde': {
            url: '/images/Hombres/Camisetas/Cuello Redondo/Verde/Camiseta-Cuello-Redondo-Verde-Cart.jpg',
            link: '/Hombre/Camisetas/Camiseta-Cuello-Redondo-Regular'
        },
    },
    'Camiseta Oversize': {
        'verde': {
            url: '/images/Hombres/Camisetas/Oversize/Verde/Camiseta-Oversize-Verde-Cart.jpg',
            link: '/Hombre/Camisetas/Camiseta-Oversize'
        },
        'púrpura': {
            url: '/images/Hombres/Camisetas/Oversize/Púrpura/Camiseta-Oversize-Púrpura-Cart.jpg',
            link: '/Hombre/Camisetas/Camiseta-Oversize'
        },
        'negro': {
            url: '/images/Hombres/Camisetas/Oversize/Negro/Camiseta-Oversize-Negro-Cart.jpg',
            link: '/Hombre/Camisetas/Camiseta-Oversize'
        },
    },
    'Camisa Guayabera Cubana': {
        'blanco': {
            url: '/images/Hombres/Camisas/Guayabera/Blanco/Camisa-Guayabera-Cubana-Blanco-Cart.jpg',
            link: '/Hombre/Camisas/Camisa-Guayabera-Cubana'
        },
        'azul': {
            url: '/images/Hombres/Camisas/Guayabera/Azul/Camisa-Guayabera-Cubana-Azul-Cart.jpg',
            link: '/Hombre/Camisas/Camisa-Guayabera-Cubana'
        },
        'beige': {
            url: '/images/Hombres/Camisas/Guayabera/Beige/Camisa-Guayabera-Cubana-Beige-Cart.jpg',
            link: '/Hombre/Camisas/Camisa-Guayabera-Cubana'
        },
    },
    'Camisa Manga Corta Estampada Casual': {
        'blanco': {
            url: '/images/Hombres/Camisas/Manga Corta Estampada/Blanco/Camisa-Manga-Corta-Blanco-Cart.jpg',
            link: '/Hombre/Camisas/Camisa-Manga-Corta-Estampada-Casual'
        },
    },
    'Jeans Clásico de Corte Holgado': {
        'azul': {
            url: '/images/Hombres/Jeans/Lightweight/Azul/Jeans-Lightweight-Azul-Cart.jpg',
            link: '/Jeans/Jeans-Clásico-de-Corte-Holgado'
        },
    },
    'Jeans Skinny sin Rotos': {
        'azul': {
            url: '/images/Hombres/Jeans/Skinny/Azul/Jeans-Skinny-Azul-Cart.jpg',
            link: '/Hombre/Jeans/Jeans-Skinny-sin-Rotos'
        },
    },
    'Pantalones Elásticos y Ajustados': {
        'negro': {
            url: '/images/Hombres/Pantalones/Elásticos y Ajustados/Negro/Pantalón-Elástico-Negro-Cart.jpg',
            link: '/Hombre/Pantalones/Pantalones-Elásticos-y-Ajustados'
        },
        'café': {
            url: '/images/Hombres/Pantalones/Elásticos y Ajustados/Café/Pantalón-Elástico-Café-Cart.jpg',
            link: '/Hombre/Pantalones/Pantalones-Elásticos-y-Ajustados'
        },
        'gris': {
            url: '/images/Hombres/Pantalones/Elásticos y Ajustados/Gris/Pantalón-Elástico-Gris-Cart.jpg',
            link: '/Hombre/Pantalones/Pantalones-Elásticos-y-Ajustados'
        },
    },
    'Pantalón Cargo': {
        'café': {
            url: '/images/Hombres/Pantalones/Cargo/Café/Pantalón-Cargo-Café-Cart.jpg',
            link: '/Hombre/Pantalones/Pantalón-Cargo'
        },
        'beige': {
            url: '/images/Hombres/Pantalones/Cargo/Beige/Pantalón-Cargo-Beige-Cart.jpg',
            link: '/Hombre/Pantalones/Pantalón-Cargo'
        },
        'gris': {
            url: '/images/Hombres/Pantalones/Cargo/Gris/Pantalón-Cargo-Gris-Cart.jpg',
            link: '/Hombre/Pantalones/Pantalón-Cargo'
        },
    },
    'Short Playero con Estampado': {
        'azul': {
            url: '/images/Hombres/Shorts/Playero-Estampado/Azul/Short-Playero-Azul-Cart.jpg',
            link: '/Hombre/Shorts/Short-Playero-con-Estampado'
        },
    },
    'Short Piscinero con Estampado': {
        'gris': {
            url: '/images/Hombres/Shorts/Piscinero-Estampado/Gris/Short-Piscinero-Gris-Cart.jpg',
            link: '/Hombre/Shorts/Short-Piscinero-con-Estampado'
        },
    },
    'Bermuda Slim en Jean': {
        'azul': {
            url: '/images/Hombres/Bermudas/Slim/Azul/Bermuda-Slim-Jean-Azul-Cart.jpg',
            link: '/Hombre/Bermudas/Bermuda-Slim-Jean'
        },
    },
    'Bermuda en Drill Unicolor': {
        'azul': {
            url: '/images/Hombres/Bermudas/Drill/Azul/Bermuda-Drill-Unicolor-Azul-Cart.jpg',
            link: '/Hombre/Bermudas/Bermuda-Drill-Unicolor'
        },
    },
};

function productoMenosStock() {
    let minStock = Infinity;
    let productoRecomendado = '';
    let linkRecomendado = '';

    for (let producto in stock) {
        for (let color in stock[producto]) {
            for (let talla in stock[producto][color]) {
                if (stock[producto][color][talla] < minStock) {
                    minStock = stock[producto][color][talla];
                    productoRecomendado = `${producto} en color ${color} y talla ${talla}`;
                    linkRecomendado = productImages[producto]?.[color]?.link || '';
                }
            }
        }
    }
    return { recomendacion: productoRecomendado, link: linkRecomendado };
}

app.get('/recomendar/menos-stock', (req, res) => {
    const { recomendacion, link } = productoMenosStock();
    res.json({ recomendacion, link });
});

const productosTemporada = {
    'verano': ['Camiseta de Cuello Redondo Regular', 'Bermuda en Drill Unicolor', 'Short Playero con Estampado'],
    // Agrega más categorías por temporada
};

function recomendarPorTemporada(temporada) {
    let productos = productosTemporada[temporada];
    let recomendacion = productos[Math.floor(Math.random() * productos.length)];
    return recomendacion;
}

app.get('/recomendar/temporada', (req, res) => {
    const temporada = req.query.temporada || 'verano'; // Por defecto 'verano'
    const recomendacion = recomendarPorTemporada(temporada);
    res.json({ recomendacion });
});

function prendaAleatoria() {
    let productos = Object.keys(stock);
    let indiceAleatorio = Math.floor(Math.random() * productos.length);
    let productoAleatorio = productos[indiceAleatorio];
    
    // Suponiendo que cada producto tiene un color predeterminado o el primer color disponible
    let colorPredeterminado = Object.keys(productImages[productoAleatorio])[0];
    let linkAleatorio = productImages[productoAleatorio][colorPredeterminado]?.link || '';

    return { recomendacion: productoAleatorio, link: linkAleatorio };
}

app.get('/recomendar/aleatorio', (req, res) => {
    const { recomendacion, link } = prendaAleatoria();
    res.json({ recomendacion, link });
});

// Crear el modelo de producto con el esquema.
const Product = mongoose.model('Product', productSchema, 'Products');

// Endpoint para agregar un nuevo producto
app.post('/products', async (req, res) => {
    const { categoria, tipo, nombre, detalles, cantidad } = req.body;
    const { tipoPrenda, color, talla, precio } = detalles;

    try {
        // Comprobar primero el stock disponible para el producto
        const productStock = stock[nombre]; // Usar `nombre` para buscar en el stock
        if (!productStock) {
            return res.status(404).json({ message: 'Producto no encontrado en el stock.' });
        }

        const colorStock = productStock[color];
        if (!colorStock) {
            return res.status(404).json({ message: 'Color no encontrado en el stock.' });
        }

        // Obtener la información de la imagen y el enlace
        const imageInfo = productImages[nombre]?.[color]; // Ahora esto es un objeto con url y link
        if (!imageInfo) {
            return res.status(404).json({ message: 'Imagen no encontrada para el color especificado.' });
        }

        const sizeStock = colorStock[talla];
        if (sizeStock === undefined) {
            return res.status(404).json({ message: 'Talla no encontrada en el stock.' });
        }

        // Si hay cantidad suficiente en el stock, proceder a crear o actualizar el producto
        if (sizeStock < cantidad) {
            return res.status(400).json({ message: 'No hay suficiente producto en inventario.' });
        }

        // Buscar un producto existente que coincida con los atributos
        let product = await Product.findOne({
            categoria,
            tipo,
            nombre,
            'detalles.tipoPrenda': tipoPrenda,
            'detalles.color': color,
            'detalles.talla': talla,
            'detalles.precio': precio
        });

        // Si el producto ya existe, actualiza la cantidad
        if (product) {
            // Asegurarse de que no se supera la cantidad del stock
            if (product.cantidad + cantidad <= sizeStock) {
                product.cantidad += cantidad;
                product.detalles.imagen = imageInfo.url;
                product.detalles.link = imageInfo.link;
                await product.save();
            } else {
                return res.status(400).json({ message: 'No hay suficiente producto en inventario.' });
            }
        } else {
            // Asegúrate de incluir la URL de la imagen en el objeto detalles
            const productDetailsWithImageAndLink = { ...detalles, imagen: imageInfo.url, link: imageInfo.link };
            // Si no existe, crea un nuevo producto asegurándose de que no supera el stock
            if (cantidad <= sizeStock) {
                product = new Product({
                    categoria,
                    tipo,
                    nombre,
                    detalles: productDetailsWithImageAndLink,
                    cantidad
                });
                await product.save();
            } else {
                return res.status(400).json({ message: 'La cantidad excede el stock disponible para un nuevo producto.' });
            }
        }

        res.status(201).json(product);
    } catch (error) {
        res.status(500).json({ message: 'Error al agregar producto: ' + error.message });
    }
});

// Endpoint para obtener todos los productos
app.get('/products', async (req, res) => {
    try {
        const products = await Product.find({});
        res.status(200).send(products);
    } catch (error) {
        res.status(500).send({ message: 'Error al recuperar productos.' });
    }
});

// Endpoint para obtener la cantidad total de productos en el carrito
app.get('/cart/count', async (req, res) => {
    try {
        const products = await Product.find({});
        const totalCount = products.reduce((sum, product) => sum + product.cantidad, 0);
        res.status(200).json({ count: totalCount });
    } catch (error) {
        res.status(500).json({ message: 'Error al recuperar la cantidad total de productos.' });
    }
});

// Endpoint para obtener un producto por ID
app.get('/products/:id', async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) {
            return res.status(404).send({ message: 'Producto no encontrado.' });
        }
        res.status(200).send(product);
    } catch (error) {
        res.status(500).send({ message: 'Error al recuperar el producto.' });
    }
});

// Endpoint para obtener un producto por ID y verificar el stock disponible
app.get('/products/:id/stock', async (req, res) => {
    try {
        // Busca el producto en la base de datos por su ID
        const product = await Product.findById(req.params.id);
        if (!product) {
            return res.status(404).send({ message: 'Producto no encontrado.' });
        }

        // Busca el stock disponible para ese producto
        const productStock = stock[product.nombre];
        if (!productStock) {
            return res.status(404).json({ message: 'Producto no encontrado en el stock.' });
        }

        const colorStock = productStock[product.detalles.color];
        if (!colorStock) {
            return res.status(404).json({ message: 'Color no encontrado en el stock.' });
        }

        const sizeStock = colorStock[product.detalles.talla];
        if (sizeStock === undefined) {
            return res.status(404).json({ message: 'Talla no encontrada en el stock.' });
        }

        // Responde con la información del producto y la cantidad en stock
        res.status(200).json({ product, stock: sizeStock });
    } catch (error) {
        res.status(500).send({ message: 'Error al recuperar el producto y su stock.' });
    }
});

// Endpoint para actualizar un producto por ID
app.put('/products/:id', async (req, res) => {
    try {
        // Obten el producto que se quiere actualizar
        const productToUpdate = await Product.findById(req.params.id);

        // Valida contra el stock
        const stockQuantity = stock[productToUpdate.nombre][productToUpdate.detalles.color][productToUpdate.detalles.talla];
        if (req.body.cantidad > stockQuantity) {
            return res.status(400).send({ message: 'Cantidad solicitada excede el stock disponible.' });
        }

        // Si la validación es correcta, actualiza el producto
        const updatedProduct = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
        if (!updatedProduct) {
            return res.status(404).send({ message: 'Producto no encontrado.' });
        }
        res.status(200).send(updatedProduct);
    } catch (error) {
        res.status(500).send({ message: 'Error al actualizar el producto.' + error });
    }
});


// Endpoint para eliminar un producto por ID
app.delete('/products/:id', async (req, res) => {
    try {
        const deletedProduct = await Product.findByIdAndDelete(req.params.id);
        if (!deletedProduct) {
            return res.status(404).send({ message: 'Producto no encontrado.' });
        }
        res.status(200).send(deletedProduct);
    } catch (error) {
        res.status(500).send({ message: 'Error al eliminar el producto.' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});