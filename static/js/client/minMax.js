/*
 * Minimize and Maximize of the Header, groupNav und Footer Element in Pad View
 * 
 */

$(document).ready(function() {
	// minimize the elements
	$("#minimize").click(function(){
    	$('header').delay(0).slideUp(800);
   		$('#groupNav').delay(0).slideUp(800);
    	$('footer').delay(0).slideUp(800);
    	$('#minimize').delay(0).slideUp(800);
    	$('#maximize').delay(1200).slideDown(800);
   	});
       	
   	// maximize the elements		
  	$("#maximize").click(function(){
   		$('header').delay(300).slideDown(800);
   		$('#groupNav').delay(300).slideDown(800);
   		$('footer').delay(300).slideDown(800);
   		$('#minimize').delay(1500).slideDown(800);
    	$('#maximize').delay(0).slideUp(800);
   	});
});