import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import portrait from './photoOfMe.png';
import resume from './AustinDoll_resume-converted.pdf';
import kubernetesLogo from './logos/kubernetes.png';
import nodeLogo from './logos/nodeLogo.png';
import dockerLogo from './logos/dockerLogo.png';
import pcfLogo from './logos/pcfLogo.png';
import awsLogo from './logos/awsLogo.png';

//define button class -- set the name and onclick that we inherit from the bodyFeild class.
class Buttons extends React.Component {
  constructor(props) {
    super(props)
    this.handleClick = this.handleClick.bind(this);
  }

  //will need to test but I do believe that this will be deprecated and done a seperate way
  handleClick(i) {
    //change both <bodyFeild or another div added later> as well as the PageDescription and Project descriptoon

  }
  render() {
    return (
      <a href="/#" name={this.props.name} onClick={this.props.buttonClick} class={this.props.class}>{this.props.name}</a>
    );
  }
}

//each page has its own class and is checked for by an if else statement for which one to be displayed
//There are still some calls to the database as it stores the formatted text appropriately which makes things a bit easier :)
class Home extends React.Component {
  render() {
    return (
      <div id="homewrapper">
        <div id="homeleft">
        <h1 class="Heading">{this.props.heading}</h1>
        {this.props.navBar}
        </div>
        <div id="contentRight">
            <div id="RightWrapper">
              <img src={portrait} alt="Autin Doll" id="portrait" />
                <p id="homeProject">
                Hello! My name is Austin Doll; I graduated from Central Michigan University in 2018 with a major in Computer Science. I have spent the last three years working at Dynatrace as both a Consultant and a Customer Solutions Engineer. During my time in these roles, I have worked with just about every cloud provider available and became certified in both Kubernetes and Cloud Foundry. In the future, I hope to be in a position to use my knowledge of APM software along with container orchestration to move into a cloud or platform engineering role. The wonderful thing about being in my current position is that I have been allowed to be exposed to just about every platform and technology under the sun. Coming out of college, I did not have a firm idea of what I wanted to do within the Computer Science field. With so many choices, it was impossible to know without giving something a shot. Over time, I found myself more drawn to infrastructure, in particular cloud infrastructure. It made sense to me to get familiar with containers as that seems to be the trend lately. Now, having a strong troubleshooting foundation and a firm understanding of how all of the pieces fit together I feel confident and ready to take on any challenges that may come my way.                </p>
                <p>
                Outside of work, I enjoy Disc Golfing and riding my longboard during the summer, and praying the cold away during the winters. One of the hobbies that take up most of my time is cooking! I love cooking just about any cuisine I can get my hands on. My current favorites are Italian and Thai-style noodles. Along with all of this, I am an avid board game fanatic and absolutely love getting together with some friends and trying out something new.
                </p>
            </div>
          </div>
      </div>
    );
  }
}


class WebScraper extends React.Component {
  render() {
    return (
      <div id="welcomeWrapper">
          <div id="welcomeleft">
            <h1 class="Heading">WebScraper</h1>
            {this.props.navBar}
          </div>
          <div id="contentRight">
            <div id="RightWrapper">
              <div id="projectDescription">
                <p>
                  Initially, I started working on this project to gain a bit more knowledge on how web requests work and GO as a language. The first step I took here was to get it running within the command line. This started me in a good spot so I could focus on learning the syntax of the language and the ins and outs of the package I was using. From there, I decided to move it into the web versus running it through the command line. I then hosted this in (at the time) Pivotal Web Services, where I could access this application through the web and download the image in a packaged zip file. Overall I learned a bit about how web apps work and some of the pitfalls of not pre-planning how to handle more than just a single user.
                </p>
              </div>
              <div id={this.props.page}>
                <pre>
                {this.props.codeText}
                </pre>
              </div>
              <div id="additonalText">
                <p>
                In the code above, I assigned functions to the response and reqeust to keep track of the URLS that I had visited to avoid downloading two of the same image, which also applied to favicons and smaller images. On response, I set up a function called 'save' that would store the images locally and print an exit line of 'visited' to show that the image was downloaded and a new URL would be queued to be scrapped for images.1
                </p>
              </div>
            </div>
          </div>
      </div>
    );
  }
}


class Portfolio extends React.Component {
  render() {


    return (
        <div id="welcomeWrapper">
            <div id="welcomeleft">
              <h1 class="Heading">Portfolio Project</h1>
              {this.props.navBar}
            </div>
            <div id="contentRight">
              <div id="RightWrapper">
                <div id="projectDescriptionHome">
                <div id="portfolioBody">
                <p>I set off to learn how a full-stack application is built and developed. I wanted to build something of my own that would give me confidence in my knowledge of how applications work and learn more about how tools like GitHub can be used to control how my app is versioned and built. When I started working on this project, I lacked knowledge of JavaScript or connecting apps from the frontend to the database. This project will most likely be ever-evolving as I learn new technologies, improve the general layout and style of this website, and add new projects as I bring them to competition. I also have a passion for Kubernetes and want to become a de facto expert in it. I started by getting Kubernetes Administrator certified. I am using a single node cluster to run this application. By doing this, I learned how different components can reach out to each other in a kube-manner and how microservices and applications can be efficiently ran in the cloud/containerized. If you have any questions or want to get ahold of me for an opportunity, please check out my contact page and reach out however you prefer!</p>
                  <div id="portfolioRight">
                  <div id="portfolioYaml">
                  <p>FROM node:latest</p>
                  <p>WORKDIR /app</p>
                  <p>COPY ["package.json", "./"]</p>
                  <p>RUN npm install</p>
                  <p>COPY . .</p>
                  <p>EXPOSE 3000</p>
                  <p>CMD ["npm", "start"]</p>
                  </div>
                  <div id ="test">
                    <a href="https://github.com/doll94av/fullstack-development" class="testbutton">Github Repo</a>
                  </div>
                  </div>
                  <p>On the right, I have included my Dockerfile as an example; both the frontend and backend use a similar layout. The foundation of this project started with the goal of being able to implement a full-stack project. It only made sense to start with the smallest building block I can with a Dockerfile. Simply put, this Dockerfile gathers the latest image from the node, copies both of my package scripts for startup, install NPM then starts my application. A minor improvement I could make is actually producing a production-level application with npm build over npm start. Still, for this project, a quicker startup time is helpful for the constant changes in the source code. I have pushed this file to Dockerhub and use this as a base for my Kubernetes deployment definition. Both the frontend and backend run in single pod deployments, which is not optimal for high availability, but it keeps the cost down for personal projects 😊. From there, I exposed both deployments publicly, with the frontend being the IP/pod combo that you are accessing this website at. Overall, this portion of the project provided a bit of hands-on from start to finish Kubernetes experience that I felt that I needed.
                  </p>
                </div>
                </div>
              </div>
            </div>
      	</div>
    );
  }
}

class Contact extends React.Component {
  render() {
    return (
      <div id="welcomeWrapper">
          <div id="welcomeleft">
            <h1 class="Heading">Contact</h1>
            {this.props.navBar}
          </div>
          <div id="contentRight">
            <div id="RightWrapper">
              <p>Please feel free to contact me using any of the below:</p>
              <p>Email: austindoll94@gmail.com</p>
              <p>Phone: (248) 820-9684</p>
              <p>LinkedIn: <a href="https://www.linkedin.com/in/austindoll40/">Linkedin.com/austindoll40</a></p>
            </div>
          </div>
      </div>
    );
  }
}

class Resume extends React.Component {
  render() {
    return (
      <div id="welcomeWrapper">
          <div id="welcomeleft">
            <h1 class="Heading">Resume</h1>
            {this.props.navBar}
          </div>
          <div id="resumeRight">
            <div id="resumeRightWrapper">
              <iframe src="https://drive.google.com/file/d/1BtIa6aOAowaVkKtXSx783J3FPJHdlROL/preview" class="importedResume" allow="autoplay"></iframe>
            </div>
          </div>
      </div>
    );
  }
}

//most of the main work is done here, construct the button nav bar as well as create the text feilds that are filled using the backend
class BodyFeild extends React.Component {
  //default text
  state = {
    generalText: <p class="Heading">Welcome!</p>,
    projectText: 'Welcome to my portfolio! Thank you for stopping by to check it out. This is an ever evolving website as I dive into the (MERN) stack. I initally started with only a basic understanding of web development but have slowly been building my knowledge base as I have worked on this project. I am working on pushing some change every day as well as running this on a small node (ec2 can get expensive) so this site may be up or down depending on if I am actively working on it or if the backend gets evicted due to resource congestion.',
    codeText: '',
    additonalText: 'take your shoes off and stay awhile :D'
  }

  //what we want to do is dynamically grab the relevant information such as grabbing information from the mongo backend!!!
  grabNewText(event) {

    //currently this works with no spaces (might want to add logic to trim spaces if I really care about it)
    //Strucutre in the backend mimics what we have in the frontend so sending data back and fourth is clear
    //fetch('http://localhost:3001/'+ event.target.name)
    //fetch('portfolio-backend.default.svc.cluster.local:3001/'+ event.target.name)
    //  .then(response => response.json())
    //  .then(data =>
    //    this.setState({
    //      generalText: <h1>{data.generalText}</h1>,
    //     projectText: data.projectText,
     //     codeText: data.codeText,
    //      additonalText: data.additonalText,
    //      page: event.target.name
    //    }),
    //  );

    //this is the button that was clicked
    this.clickedHome=event.target.name;
  }


  render() {

    //if there is a need to add a new button, all that should be needed is to add it to this list and create a get endpoint in the node Backend
    //essentially we cycle through the array and add the name property and assign it the bodyFeild getNewText for its onClick

    //testing homepage
    var buttonList = ["Home", "Resume", "WebScraper", "Portfolio", "Contact"];
    for(var i = 0; i < buttonList.length; i++) {
      buttonList[i] = <Buttons name={buttonList[i]} buttonClick={this.grabNewText.bind(this)} class="welcomeButton"/>
    }
    const listedButtons = buttonList.map((button) =>
     button
    );

    var clickedHome = "Home";
    if(clickedHome === this.clickedHome){

      return (

        //simply place relevant divs, within each div set the relevant state to place text
        //the state is changed within the grabNewText OnClick, all data is pulled from the mongoDB that backs this
        <Home navBar={listedButtons} heading="Home"/>
      );
    }
    else if("Contact" === this.clickedHome){

      return (
      //simply place relevant divs, within each div set the relevant state to place text
      //the state is changed within the grabNewText OnClick, all data is pulled from the mongoDB that backs this
        <Contact  navBar={listedButtons}/>
      );
    }
    else if("Portfolio" === this.clickedHome){

      return (
      //simply place relevant divs, within each div set the relevant state to place text
      //the state is changed within the grabNewText OnClick, all data is pulled from the mongoDB that backs this
        <Portfolio navBar={listedButtons}/>
      );
    }
    else if("WebScraper" === this.clickedHome){
      return (
      //simply place relevant divs, within each div set the relevant state to place text
      //the state is changed within the grabNewText OnClick, all data is pulled from the mongoDB that backs this
        <WebScraper codeText={this.state.codeText} page={this.state.page} navBar={listedButtons}/>
      );
    }
    else if("Resume" === this.clickedHome){
      return (
      //simply place relevant divs, within each div set the relevant state to place text
      //the state is changed within the grabNewText OnClick, all data is pulled from the mongoDB that backs this
        <Resume codeText={this.state.codeText} page={this.state.page} navBar={listedButtons}/>
      );
    } else return (
        <div id="welcomeWrapper">
            <div id="welcomeleft">
              <div id="test2">
              <h1 class="Heading">Welcome</h1>
              </div>
              {listedButtons}
            </div>
            <div id="contentRight">
              <div id="RightWrapper">
                <p>
                  Welcome to my portfolio! Thank you for stopping by to check it out. This is an ever-evolving website as I dive into the (MERN) stack. I initially started with only a basic understanding of web development but have slowly built my knowledge base as I have worked on this project. I am pushing some change every day and running this on a small node (ec2 can get expensive), so this site may be up or down depending on whether I am actively working on it or if the backend gets evicted due to resource congestion.
                </p>
                <div id="welcomeFooter">
                  <img src={kubernetesLogo} alt="Kubernetes" class="welcomeImages" />
                  <img src={nodeLogo} alt="node.js" class="welcomeImages" />
                  <img src={dockerLogo} alt="Docker" class="welcomeImages" />
                  <img src={pcfLogo} alt="PCF" class="welcomeImages" />
                  <img src={awsLogo} alt="AWS" style={{width: "180px"}}/>
                </div>
              </div>
            </div>
      </div>
    );
  }
}

ReactDOM.render(
  <BodyFeild />,
  document.getElementById('root')
)
