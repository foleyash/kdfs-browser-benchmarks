import { get } from "http"

export async function POST(request : Request) {
    const body = await request.json(); // body contains list 
    const res = await fetch('https://sheetdb.io/api/v1/l0tsnuv3ihrg4', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {' + process.env.NEXT_PUBLIC_API_TOKEN + '}'
      },
      body: JSON.stringify({
        data: body, // Add 
      })
      
      
      
    })
    const data = await res.json()
   
    return Response.json({ data })
  }