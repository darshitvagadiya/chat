angular.module('Instagram')
	.factory('API', function($http){
		return{
			postChat: function(){
				return $http.post('http://localhost:3000/chat');
			}
		}
	});