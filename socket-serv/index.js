const express = require("express");
const app = express();
const http = require("http");
const cors = require("cors");
const {Server} = require("socket.io")
;
app.use(cors());

const server = http.createServer(app);

const io = new Server(server,{
    cors:{
        origin: "https://gossip-frontend.vercel.app",
        mathods: ["GET", "POST"]
    }
})

io.on("connection", (socket)=>{
    console.log(`User connected: ${socket.id}`)
  
  
        socket.on("add_room", (data)=>{
          console.log("SOCKET")
          console.log(data)
          io.emit("new_room", data)
        }
        )
  
        socket.on("join_room", (data)=>{
            socket.join(data);
            console.log(`User with ID: ${socket.id} joined room: ${data}`)
        })
  
        socket.on("leave_room", (data)=>{
          socket.leave(data);
          console.log(`User with ID: ${socket.id} left room: ${data}`)
      })
  
  
        socket.on("send_message", (data) =>{
            socket.to(data.room).emit("receive_message", data)
        } )
  
    socket.on("disconnect", ()=>{
        console.log("User disconnected", socket.id)
    })
  })

let port = process.env.PORT || 3001;
server.listen(port, () => console.log(`Listening on port ${port}`));