/*
 * Utils
 */

Bitponics.Utils = {
	
	toTitleCase: function(str) {
    return str.replace(/(?:^|\s)\w/g, function(match) {
        return match.toUpperCase();
    });
	},

	setupPages: function($navElements) {
		var self = this;
		
		$navElements.each(function(){
				var $this = $(this),
						url = $this.attr('href').replace('/', '');

		    $('#main').append('<div id="' + url + '" class="content-module middle"></div>');
				$this.attr('href', '#'+url);

		    self.includePage({
		        'url': url,
		        'remoteSelector': '#main > *',
		        'localElement': '#main > #' + url
		    });
		});

	},

	includePage: function(settings) {

	    $.ajax({
	        url: settings.url,
	        dataType: 'html'
	    })
	    .success(function() { console.log('success'); })
	    .error(function() { console.log('error'); })
	    .complete(function(res, status) {
	        if (status === 'success' || status === 'notmodified') {
		    		$(settings.localElement).append($(res.responseText).find(settings.remoteSelector));
	        } else {
            console.log('bad response:');
            console.log(res.responseText);
     	  	}
	    });

	},

	sectionHeightAlign: function(minHeight, sectionSelector) {
		var screenHeight = $(window).height() > minHeight ? $(window).height() : minHeight;
    
    $(sectionSelector).each(function(i) {
    	var section = $(this),
    			sectionHeight = section.height();
    	
    	if (i == 0) {
    		section.height(screenHeight);
    	} else {
    		setTimeout(function() {
    			sectionHeight = section.height();
    			if(sectionHeight < minHeight) {
    				section.height(screenHeight);
    			}
    		}, 1000);
    	}

    });
    	
	}

}