--#ENDPOINT GET /tsdb

response.message = {
	Tsdb.query(from_json(request.parameters.query)),
	from_json(request.parameters.query),
}
