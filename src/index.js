import dotenv from "dotenv";
import connectDB from "./db/index.js";
import { app } from "./app.js";


dotenv.config({ path: './env' });

connectDB().then(() => {
    app.listen(process.env.PORT || 8000, () => {
        console.log(`Server is running at http://localhost:${process.env.PORT}`);
    });
}).catch((error) => {
    console.log("Error in connecting to DB", error);
    process.exit(1);
});