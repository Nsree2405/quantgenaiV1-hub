import { ResourceType, Topic, Paper, Resource, VideoTutorial } from '../types';

export const topics: Topic[] = [
  {
    id: '1',
    title: 'Machine Learning', 
    slug: 'machine-learning', 
    shortDescription: 'Algorithms that improve automatically through experience',
    description: 'Machine learning is a field of inquiry devoted to understanding and building methods that "learn" – that is, methods that leverage data to improve performance on some set of tasks. It is seen as a part of artificial intelligence.',
    overview:'Machine learning enables computers to automatically discover patterns in data and make predictions without being explicitly programmed. It is widely used in various domains, including healthcare, finance, robotics, and more.',
    keypoints:'Machine learning relies on several fundamental concepts that guide its development and application:',
    p1:'Supervised Learning: The model learns from labeled data, mapping inputs to known outputs (e.g., spam email detection).',
    p2:'Unsupervised Learning: The model finds patterns and structures in unlabeled data (e.g., customer segmentation).',
    p3:'Reinforcement Learning: The model learns by interacting with the environment and receiving rewards or penalties (e.g., game-playing AI).',
    p4:'Overfitting and Underfitting: Overfitting occurs when a model learns noise instead of the actual pattern, while underfitting happens when it fails to learn sufficiently.',
    p5:'Feature Engineering: Selecting and transforming input variables to improve the model\'s performance',
    p6:'Model Evaluation: Methods such as accuracy, precision, recall, and F1-score help assess a model\'s effectiveness.',
    c1:'Machine learning continues to evolve, with advancements in deep learning, transfer learning, and generative AI driving innovation in various industries.',
    applications:'Machine Learning is transforming various industries by enabling systems to learn from data and make intelligent decisions. Some key applications include:',
    a1:'Healthcare: ML is used for disease diagnosis, personalized treatment plans, and drug discovery.',
    a2:'Finance: Fraud detection, algorithmic trading, and credit risk assessment leverage ML models.',
    a3:'Retail & E-commerce: Personalized recommendations, demand forecasting, and customer sentiment analysis improve user experience.',
    a4:'Autonomous Vehicles: ML powers self-driving cars by helping them detect objects, recognize road signs, and navigate safely.',
    a5:'Natural Language Processing (NLP): AI-driven chatbots, language translation, and sentiment analysis enhance communication.',
    a6:'Manufacturing: Predictive maintenance and quality control optimize production processes.',
    a7:'Cybersecurity: ML detects anomalies and prevents cyber threats in real-time.',
    c2:'Machine Learning continues to evolve, leading to more advanced applications in multiple fields.',
    videoUrl: 'https://www.youtube.com/watch?v=6mSx_KJxcHI',
    image: 'https://images.unsplash.com/photo-1488229297570-58520851e868?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=2069&q=80',
    papers: [
      {
        id: 'ml-paper-1',
        title: 'A Few Useful Things to Know About Machine Learning',
        authors: 'Pedro Domingos',
        year: '2012',
        link: 'https://homes.cs.washington.edu/~pedrod/papers/cacm12.pdf',
        abstract: 'This paper provides a very high-level overview of machine learning concepts and best practices.'
      },
      {
        id: 'ml-paper-2',
        title: 'Machine Learning: Trends, Perspectives, and Prospects',
        authors: 'M. I. Jordan, T. M. Mitchell',
        year: '2015',
        link: ' https://www.cs.cmu.edu/~tom/pubs/Science-ML-2015.pdf',
        abstract: 'A survey of machine learning and where it may be headed.'
      },
      {
        id: 'ml-paper-3',
        title: 'Explaining and Harnessing Adversarial Examples',
        authors: 'Ian J. Goodfellow, Jonathon Shlens, Christian Szegedy',
        year: '2015',
        link: 'https://arxiv.org/pdf/1412.6572',
        abstract: 'This paper explains why neural networks are vulnerable to adversarial examples and proposes a fast method of generating them.'
      },
      {
        id: 'ml-paper-4',
        title: 'XGBoost: A Scalable Tree Boosting System',
        authors: 'Tianqi Chen, Carlos Guestrin',
        year: '2016',
        link: 'https://arxiv.org/pdf/1603.02754',
        abstract: 'This paper describes the XGBoost system, which is a highly effective and widely used gradient boosting implementation.'
      },
      {
        id: 'ml-paper-5',
        title: 'The Lottery Ticket Hypothesis: Finding Sparse, Trainable Neural Networks',
        authors: 'Jonathan Frankle, Michael Carbin',
        year: '2019',
        link: 'https://arxiv.org/pdf/1803.03635',
        abstract: 'This paper introduces the concept that within large neural networks exist smaller subnetworks that can be trained to similar performance.'
      },
      {
        id: 'ml-paper-6',
        title: 'Faster R-CNN: Towards Real-Time Object Detection with Region Proposal Networks',
        authors: 'Shaoqing Ren, Kaiming He, Ross Girshick, Jian Sun',
        year: '2016',
        link: 'https://arxiv.org/pdf/1506.01497',
        abstract: 'A seminal paper in the field of object detection, introducing a faster and more accurate approach for detecting objects in images.'
      }
    ],
    resources: [
      {
        id: '0',  //tutorials
        title: 'Introduction to ' + 'Machine Learning',
        description: 'Learn the fundamentals of ' + 'Machine Learning',
        link: 'https://www.geeksforgeeks.org/machine-learning/',
        type: ResourceType.Tutorial 
      },
      {
        id: '1',  //tutorials
        title: 'Machine Learning ' + 'Using Python',
        description: 'Learn the fundamentals of ' + 'Machine Learning',
        link: 'https://www.w3schools.com/python/python_ml_getting_started.asp',
        type: ResourceType.Tutorial 
      },
      {
        id: '2',  //tutorials
        title: 'Learn about '+'Machine Learning ' ,
        description: 'Learn the fundamentals of ' + 'Machine Learning',
        link: 'https://www.tutorialspoint.com/machine_learning/index.htm',
        type: ResourceType.Tutorial 
      },
      {
        id: '3',  //tutorials
        title: 'Get on '+'Machine Learning ' ,
        description: 'Learn the fundamentals of ' + 'Machine Learning',
        link: 'https://www.tpointtech.com/machine-learning',
        type: ResourceType.Tutorial 
      },
      {
        id: '2', //courses
        title: 'Advanced ' + 'Machine Learning' + ' Concepts',
        description: 'Deep dive into advanced topics and applications',
        link: 'https://developers.google.com/machine-learning/crash-course',
        type: ResourceType.Course
      },
      {
        id: '3', // videos 
        title: 'Machine Learning' + ' Fundamentals Video',
        description: 'Video tutorial covering the basics of ' + 'Machine Learning',
        link: 'https://youtu.be/JxgmHe2NyeY?si=2DF4k21NHNLNpQaI',
        type: ResourceType.Video
      },
      {
        id: '4',
        title: 'Advanced ' + 'Machine Learning' + ' Techniques Video',
        description: 'Deep dive into advanced concepts and applications',
        link: 'https://www.youtube.com/watch?v=NWONeJKn6kc',
        type: ResourceType.Video
      }
    ],
    videoTutorials: [
      {
        id: 'ml-video-1',
        title: 'Machine Learning Fundamentals',
        duration: '12:44',
        thumbnail: 'https://images.unsplash.com/photo-1488190211105-8b0e65b80b4e?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=60',
        videoUrl: 'https://www.youtube.com/watch?v=Gv9_4yMHFhI&list=PLblh5JKOoLUICTaGLRoHQDuF_7q2GfuJF&ab_channel=StatQuestwithJoshStarmer',
        description: 'An introduction to the core concepts of machine learning with practical examples.'
      },
      {
        id: 'ml-video-2',
        title: 'Neural Networks Explained',
        duration: '38:15',
        thumbnail: 'https://images.unsplash.com/photo-1507146153580-69a1fe6d8aa1?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=60',
        videoUrl: 'https://www.youtube.com/embed/aircAruvnKk',
        description: 'A visual and intuitive explanation of neural networks and how they work.'
      }
    ]
  },
  {
    id: '2',
    title: 'Deep Learning',
    slug: 'deep-learning',
    shortDescription: 'Neural networks with multiple layers that learn representations',
    description: 'Deep learning is part of a broader family of machine learning methods based on artificial neural networks with representation learning. Learning can be supervised, semi-supervised or unsupervised.',
    overview: 'Deep learning is a subset of machine learning that utilizes artificial neural networks to automatically extract patterns from large datasets. It powers many AI applications, from image recognition to natural language processing.',
    keypoints: 'Deep learning relies on several fundamental concepts that enable its capabilities:',
    p1: 'Neural Networks: Multi-layered structures that process data similarly to the human brain.',
    p2: 'Backpropagation: An optimization technique that adjusts neural network weights to improve accuracy.',
    p3: 'Activation Functions: Mathematical functions like ReLU and Sigmoid that determine neuron outputs.',
    p4: 'Overfitting & Regularization: Preventing overfitting using techniques like dropout and batch normalization.',
    p5: 'Transfer Learning: Using pre-trained models to improve learning efficiency on new tasks.',
    p6: 'Computational Requirements: Requires GPUs and TPUs for processing large-scale datasets efficiently.',
    c1: 'Deep learning continues to advance, driving innovations in AI applications across multiple industries.',
    applications: 'Deep learning enables intelligent systems across multiple domains:',
    a1: 'Healthcare: AI-powered diagnosis, drug discovery, and medical image analysis.',
    a2: 'Autonomous Vehicles: Enables perception, object detection, and path planning in self-driving cars.',
    a3: 'Finance: Algorithmic trading, fraud detection, and risk assessment models.',
    a4: 'Natural Language Processing (NLP): AI-driven chatbots, voice assistants, and language translation.',
    a5: 'Robotics: Intelligent robots for industrial automation and human assistance.',
    a6: 'Entertainment: AI-generated music, movies, and personalized content recommendations.',
    a7: 'Cybersecurity: Deep learning models detect malware and prevent cyber threats in real time.',
    c2:'',
    videoUrl: 'https://www.youtube.com/watch?v=6M5VXKLf4D4',
    image: 'https://images.unsplash.com/photo-1544654803-b69140b285a1?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=2070&q=80',
    papers: [
      {
        id: 'dl-paper-1',
        title: 'Deep Learning',
        authors: 'Y. LeCun, Y. Bengio, G. Hinton',
        year: '2015',
        link: 'https://www.nature.com/articles/nature14539',
        abstract: 'Review paper that presents the basics of deep learning.'
      },
      {
        id: 'dl-paper-2',
        title: 'ImageNet Classification with Deep Convolutional Neural Networks',
        authors: 'A. Krizhevsky, I. Sutskever, G. E. Hinton',
        year: '2012',
        link: ' https://proceedings.neurips.cc/paper/4824-imagenet-classification-with-deep-convolutional-neural-networks.pdf',
        abstract: 'The paper that rekindled interest in CNNs and deep learning.'
      },
      {
        id: 'dl-paper-3',
        title: 'Generative Adversarial Nets',
        authors: 'Ian J. Goodfellow et al.',
        year: '2014',
        link: 'https://arxiv.org/pdf/1406.2661',
        abstract: 'This paper introduces GANs, which create a framework for training generative models through an adversarial process.'
      },
      {
        id: 'dl-paper-4',
        title: 'Adam: A Method for Stochastic Optimization',
        authors: 'Diederik P. Kingma, Jimmy Ba',
        year: '2015',
        link: 'https://arxiv.org/pdf/1412.6980',
        abstract: 'This paper presents Adam, an algorithm for first-order gradient-based optimization of stochastic objective functions.'
      },
      {
        id: 'dl-paper-5',
        title: 'Dropout: A Simple Way to Prevent Neural Networks from Overfitting',
        authors: 'Nitish Srivastava et al.',
        year: '2014',
        link: 'https://www.jmlr.org/papers/volume15/srivastava14a/srivastava14a.pdf',
        abstract: 'This paper presents dropout, a technique for addressing the problem of overfitting in neural networks.'
      },
      {
        id: 'dl-paper-6',
        title: 'U-Net: Convolutional Networks for Biomedical Image Segmentation',
        authors: 'Olaf Ronneberger, Philipp Fischer, Thomas Brox',
        year: '2015',
        link: 'https://arxiv.org/pdf/1505.04597',
        abstract: 'This paper introduces the U-Net architecture, which has become a standard for image segmentation tasks, especially in medical imaging.'
      }
    ],
    resources: [
      {
        id: '0',
        title: 'Introduction to ' + 'Deep Learning',
        description: 'Learn the fundamentals of ' + 'Deep Learning',
        link: 'https://www.geeksforgeeks.org/deep-learning-tutorial/',
        type: ResourceType.Tutorial
      },
      {
        id: '1',
        title: 'Code on ' + 'Deep Learning',
        description: 'Learn the fundamentals of ' + 'Deep Learning',
        link: 'https://www.w3schools.com/ai/ai_neural_networks.asp',
        type: ResourceType.Tutorial
      },
      {
        id: '2',  //tutorials
        title: 'Dive Deep into ' + 'Deep Learning',
        description: 'Learn the fundamentals of ' + 'Deep Learning',
        link: 'https://www.tpointtech.com/deep-learning',
        type: ResourceType.Tutorial 
      },
      {
        id: '3',
        title: 'Deep Learning'+ ' using Python',
        description: 'Learn the fundamentals of ' + 'Deep Learning',
        link: 'https://www.tutorialspoint.com/python_deep_learning/index.htm',
        type: ResourceType.Tutorial
      },
      {
        id: '2',
        title: 'Advanced ' + 'Deep Learning' + ' Concepts',
        description: 'Deep dive into advanced topics and applications',
        link: 'https://techdevguide.withgoogle.com/resources/topics/deep-learning/?no-filter=true#!',
        type: ResourceType.Course
      },
      {
        id: '3',
        title: 'Deep Learning' + ' Fundamentals Video',
        description: 'Video tutorial covering the basics of ' + 'Deep Learning',
        link: 'https://www.youtube.com/watch?v=d2kxUVwWWwU',
        type: ResourceType.Video
      },
      {
        id: '4',
        title: 'Advanced ' + 'Deep Learning' + ' Techniques Video',
        description: 'Deep dive into advanced concepts and applications',
        link: 'https://www.youtube.com/watch?v=ErnWZxJovaM',
        type: ResourceType.Video
      }
    ],
    videoTutorials: [
      {
        id: 'dl-video-1',
        title: 'Deep Learning Crash Course',
        duration: '1:25:39',
        thumbnail: 'https://images.unsplash.com/photo-1522094626083-4d9be62319aa?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=60',
        videoUrl: 'https://www.youtube.com/embed/VyWAvY2CF9c',
        description: 'A comprehensive crash course covering key deep learning concepts and architectures.'
      },
      {
        id: 'dl-video-2',
        title: 'Building Neural Networks with PyTorch',
        duration: '4:35:42',
        thumbnail: 'https://images.unsplash.com/photo-1486312338219-ce68d2c6f44d?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=60',
        videoUrl: 'https://www.youtube.com/embed/c36lUUr864M',
        description: 'Learn how to build and train neural networks using the PyTorch framework.'
      }
    ]
  },
  {
    id: '3',
    title: 'Natural Language Processing',
    slug: 'nlp',
    shortDescription: 'AI that enables computers to understand and generate human language',
    description: 'Natural language processing (NLP) is a subfield of artificial intelligence concerned with the interactions between computers and human language, in particular how to program computers to process and analyze large amounts of natural language data.',
    
    overview: 'NLP allows computers to understand, interpret, and generate human language for various text and speech-related applications.',
    keypoints: 'NLP relies on multiple advanced AI concepts:',
    p1: 'Tokenization: Splitting text into words or subwords for processing.',
    p2: 'Sentiment Analysis: Identifying emotions and opinions from text data.',
    p3: 'Named Entity Recognition (NER): Extracting meaningful entities like names, locations, and dates from text.',
    p4: 'Language Modeling: Predicting and generating human-like text using deep learning models.',
    p5: 'Speech Recognition: Converting spoken language into text for AI assistants.',
    p6: 'Translation & Summarization: AI-driven tools help translate and summarize texts automatically.',
    c1: 'NLP is a rapidly growing field that enhances human-computer interaction through intelligent text and speech analysis.',
    applications: 'NLP powers a wide range of AI-driven communication tools:',
    a1: 'Chatbots: Virtual assistants like ChatGPT and Alexa.',
    a2: 'Language Translation: Google Translate for multilingual conversations.',
    a3: 'Voice Assistants: AI-powered speech recognition in smart devices.',
    a4: 'Content Summarization: AI tools condense lengthy documents.',
    a5: 'Sentiment Analysis: AI detecting emotions in customer reviews and social media.',
    a6: 'Grammar Checking: Tools like Grammarly for writing improvement.',
    a7: 'Information Retrieval: AI-enhanced search engines for quick data access.',
    c2:'',
    videoUrl: 'https://www.youtube.com/watch?v=CMrHM8a3hqw',
    image: 'https://images.unsplash.com/photo-1546410531-bb4caa6b424d?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=2071&q=80',
    papers: [
      {
        id: 'nlp-paper-1',
        title: 'Attention Is All You Need',
        authors: 'A. Vaswani et al.',
        year: '2017',
        link: 'https://arxiv.org/pdf/1706.03762',
        abstract: 'Introduces the Transformer architecture which revolutionized NLP.'
      },
      {
        id: 'nlp-paper-2',
        title: 'BERT: Pre-training of Deep Bidirectional Transformers for Language Understanding',
        authors: 'J. Devlin, M. Chang, K. Lee, K. Toutanova',
        year: '2018',
        link: 'https://arxiv.org/pdf/1810.04805',
        abstract: 'Introduces BERT, which advanced the state of the art in many NLP tasks.'
      },
      {
        id: 'nlp-paper-3',
        title: 'GPT-3: Language Models are Few-Shot Learners',
        authors: 'Tom B. Brown et al.',
        year: '2020',
        link: 'https://arxiv.org/pdf/2005.14165',
        abstract: 'Introduces GPT-3, demonstrating that language models can perform tasks without task-specific training examples.'
      },
      {
        id: 'nlp-paper-4',
        title: 'Distributed Representations of Words and Phrases and their Compositionality',
        authors: 'Tomas Mikolov et al.',
        year: '2013',
        link: 'https://arxiv.org/pdf/1310.4546',
        abstract: 'Introduces word2vec, a method for learning high-quality word vectors from large datasets.'
      },
      {
        id: 'nlp-paper-5',
        title: 'GloVe: Global Vectors for Word Representation',
        authors: 'Jeffrey Pennington, Richard Socher, Christopher D. Manning',
        year: '2014',
        link: 'https://nlp.stanford.edu/pubs/glove.pdf',
        abstract: 'Presents GloVe, an unsupervised learning algorithm for generating vector representations of words.'
      },
      {
        id: 'nlp-paper-6',
        title: 'Sequence to Sequence Learning with Neural Networks',
        authors: 'Ilya Sutskever, Oriol Vinyals, Quoc V. Le',
        year: '2014',
        link: 'https://arxiv.org/pdf/1409.3215',
        abstract: 'Introduces a general sequence learning approach using LSTM networks that can map sequences to sequences.'
      }
    ],
    resources: [
      {
        id: '0',
        title: 'Introduction to ' + 'Natural Language Processing',
        description: 'Learn the fundamentals of ' + 'Natural Language Processing',
        link: 'https://www.geeksforgeeks.org/natural-language-processing-nlp-tutorial/',
        type: ResourceType.Tutorial
      },
      {
        id: '1',
        title: 'Learn ' + 'Natural Language Processing',
        description: 'Learn the fundamentals of ' + 'Natural Language Processing',
        link: 'https://www.tutorialspoint.com/natural_language_processing/index.htm',
        type: ResourceType.Tutorial
      },
      {
        id: '2',
        title: 'Advanced ' + 'Natural Language Processing' + ' Concepts',
        description: 'Deep dive into advanced topics and applications',
        link: 'https://www.cloudskillsboost.google/course_templates/40',
        type: ResourceType.Course
      },
      {
        id: '3',
        title: 'Natural Language Processing' + ' Fundamentals Video',
        description: 'Video tutorial covering the basics of ' + 'Natural Language Processing',
        link: 'https://www.youtube.com/watch?v=ENLEjGozrio',
        type: ResourceType.Video
      },
      {
        id: '4',
        title: 'Advanced ' + 'Natural Language Processing' + ' Techniques Video',
        description: 'Deep dive into advanced concepts and applications',
        link: 'https://www.youtube.com/watch?v=M7SWr5xObkA',
        type: ResourceType.Video
      }

    ],
    videoTutorials: [
      {
        id: 'nlp-video-1',
        title: 'Introduction to NLP and Transformers',
        duration: '11:36',
        thumbnail: 'https://images.unsplash.com/photo-1617791160505-6f00504e3519?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=60',
        videoUrl: 'https://www.youtube.com/embed/xI0HHN5XKDo',
        description: 'Learn the fundamentals of NLP and how transformer models have revolutionized the field.'
      },
      {
        id: 'nlp-video-2',
        title: 'Building a Chatbot with Python',
        duration: '14:32',
        thumbnail: 'https://images.unsplash.com/photo-1499750310107-5fef28a66643?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=60',
        videoUrl: 'https://www.youtube.com/embed/Da-iHgrmHYg',
        description: 'A step-by-step tutorial on creating your own chatbot using Python and NLP techniques.'
      }
    ]
  },
  {
    id: '4',
    title: 'Robotics',
    slug: 'robotics',
    shortDescription: 'Design, construction, and use of machines to perform tasks',
    description: 'Robotics is an interdisciplinary field that integrates computer science and engineering. Robotics involves design, construction, operation, and use of robots, as well as computer systems for their perception, control, sensory feedback, and information processing.',
    overview: 'Robotics combines AI, sensors, and mechanical engineering to create intelligent machines that perform tasks autonomously or with human assistance.',
    keypoints: 'Robotics involves several key technological aspects:',
    p1: 'Artificial Intelligence: AI-driven robots learn from their environment and improve over time.',
    p2: 'Actuators & Sensors: Components that enable movement and real-time environmental interaction.',
    p3: 'Machine Vision: Cameras and sensors help robots recognize objects and navigate spaces.',
    p4: 'Automation & Control: Robotics streamlines repetitive tasks in industries like manufacturing.',
    p5: 'Human-Robot Interaction: AI enhances collaboration between robots and humans in workplaces.',
    p6: 'Ethical Concerns: The impact of robotics on employment and ethical AI decision-making is a concern.',
    c1: 'Robotics is revolutionizing industries by improving efficiency, safety, and automation across various fields.',
    applications: 'Robots are used in various industries to perform complex and repetitive tasks:',
    a1: 'Industrial Automation: Robots assemble and manufacture products with precision.',
    a2: 'Medical Robotics: Surgical robots assist in minimally invasive surgeries.',
    a3: 'Autonomous Vehicles: Self-driving robots transport goods and passengers safely.',
    a4: 'Agriculture: AI-powered robots harvest crops and monitor soil health.',
    a5: 'Military & Defense: Robots handle reconnaissance, bomb disposal, and logistics.',
    a6: 'Household Assistance: Smart home robots assist with cleaning, cooking, and security.',
    a7: "Space Exploration: Robots like NASA's rovers explore planets and analyze extraterrestrial environments.",
    c2:'',
    videoUrl: 'https://www.youtube.com/watch?v=HvMQONnCXbE',
    image: 'https://images.unsplash.com/photo-1555255707-c07966088b7b?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=2036&q=80',
    papers: [
      {
        id: 'rob-paper-1',
        title: 'A Roadmap for US Robotics: From Internet to Robotics',
        authors: 'H. Christensen et al.',
        year: '2016',
        link: ' https://hichristensen.com/pdf/roadmap-2024.pdf',
        abstract: 'A look at the future of robotics research and applications.'
      },
      {
        id: 'rob-paper-2',
        title: 'Learning Hand-Eye Coordination for Robotic Grasping with Deep Learning and Large-Scale Data Collection',
        authors: 'S. Levine et al.',
        year: '2016',
        link: ' https://arxiv.org/pdf/1603.02199',
        abstract: 'Using deep RL to teach robots fine motor skills.'
      },
      {
        id: 'rob-paper-3',
        title: 'VisuoMotor Control: Learning to Manipulate by Seeing and Feeling',
        authors: 'J. Bohg et al.',
        year: '2019',
        link: 'https://arxiv.org/pdf/1901.11103',
        abstract: 'This paper explores how visual and tactile perception can be integrated for robotic manipulation.'
      },
      {
        id: 'rob-paper-4',
        title: 'Dexterous Manipulation with Deep Reinforcement Learning: Efficient, General, and Low-Cost',
        authors: 'A. Kumar et al.',
        year: '2021',
        link: 'https://arxiv.org/pdf/2004.00704',
        abstract: 'Demonstrates how robots can learn dexterous manipulation skills through reinforcement learning.'
      },
      {
        id: 'rob-paper-5',
        title: 'Learning Quadrupedal Locomotion over Challenging Terrain',
        authors: 'J. Hwangbo et al.',
        year: '2019',
        link: 'https://www.science.org/doi/10.1126/scirobotics.aau5872',
        abstract: 'This paper shows how legged robots can learn to navigate difficult terrains using reinforcement learning.'
      },
      {
        id: 'rob-paper-6',
        title: 'SLAM: Simultaneous Localization and Mapping: Part I',
        authors: 'H. Durrant-Whyte, T. Bailey',
        year: '2006',
        link: 'https://ieeexplore.ieee.org/document/1638022',
        abstract: 'A foundational paper on SLAM techniques used for robot navigation and mapping.'
      }
    ],
    resources: [
      {
        id: '0',
        title: 'Introduction to ' + 'Robotics',
        description: 'Learn the fundamentals of ' + 'Robotics',
        link: 'https://www.geeksforgeeks.org/robotics-introduction/',
        type: ResourceType.Tutorial
      },
      {
        id: '1',
        title: 'Work on ' + 'Robotics',
        description: 'Learn the fundamentals of ' + 'Robotics',
        link: 'https://www.tutorialspoint.com/robotics/index.htm',
        type: ResourceType.Tutorial
      },
      {
        id: '2',
        title: 'Advanced ' + 'Robotics' + ' Concepts',
        description: 'Deep dive into advanced topics and applications',
        link: 'https://onlinecourses.nptel.ac.in/noc19_me74/preview',
        type: ResourceType.Course
      },
      {
        id: '3',
        title: 'Robotics' + ' Fundamentals Video',
        description: 'Video tutorial covering the basics of ' + 'Robotics',
        link: 'https://www.youtube.com/watch?v=v7c6raCx_cY',
        type: ResourceType.Video
      },
      {
        id: '4',
        title: 'Advanced ' + 'Robotics' + ' Techniques Video',
        description: 'Deep dive into advanced concepts and applications',
        link: 'https://www.youtube.com/watch?v=htjRUL3neMg',
        type: ResourceType.Video
      }
    ],
    videoTutorials: [
      {
        id: 'rob-video-1',
        title: 'Introduction to Robotics',
        duration: '21:01',
        thumbnail: 'https://images.unsplash.com/photo-1561144257-e32e8271dce9?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=60',
        videoUrl: 'https://www.youtube.com/watch?v=eqXQ80vlgqE&list=PLGs0VKk2DiYxkoe2XNxDvVHqL5XG4dMWi&ab_channel=PaulMcWhorter',
        description: 'A comprehensive introduction to robotics principles, mechanics, and control systems.'
      },
      {
        id: 'rob-video-2',
        title: 'Building Your First AI Robot',
        duration: '42:15',
        thumbnail: 'https://images.unsplash.com/photo-1535378917042-10a22c95931a?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=60',
        videoUrl: 'https://www.youtube.com/watch?v=x0oUZ4HS7lg&ab_channel=Murtaza%27sWorkshop-RoboticsandAI',
        description: 'Step-by-step guide to building a simple robot using Arduino microcontrollers.'
      }
    ]
  },
  {
    id: '5',
    title: 'Drones',
    slug: 'drones',
    shortDescription: 'Unmanned aerial vehicles with autonomous capabilities',
    description: 'Drones, or unmanned aerial vehicles (UAVs), are aircraft without human pilots on board. They can be remotely controlled or fly autonomously through software-controlled flight plans, working in conjunction with onboard sensors and GPS.',
    overview: 'Drones, also known as UAVs (Unmanned Aerial Vehicles), are autonomous or remotely controlled flying devices used for a wide range of applications, including surveillance, delivery, and emergency response.',
    keypoints: 'The evolution of drones is driven by various technological advancements:',
    p1: 'Autonomous Navigation: AI-powered drones can navigate and avoid obstacles without human intervention.',
    p2: 'Remote Sensing: Drones equipped with sensors collect aerial data for analysis.',
    p3: 'GPS Integration: Enables precise navigation and location tracking for various applications.',
    p4: 'AI and Machine Learning: Enhances drone decision-making and adaptability in real time.',
    p5: 'Battery Efficiency: Advances in battery technology improve flight duration and performance.',
    p6: 'Regulatory Compliance: Governments impose airspace restrictions and safety regulations on drone usage.',
    c1: 'Drones are reshaping industries by offering cost-effective and efficient solutions for data collection, surveillance, and automation.',
    applications: 'Drones are widely used across industries for different purposes:',
    a1: 'Agriculture: Crop monitoring, precision farming, and pesticide spraying.',
    a2: 'Delivery Services: Companies like Amazon and UPS use drones for faster deliveries.',
    a3: 'Disaster Management: Aerial surveys and search-and-rescue operations in disaster-hit areas.',
    a4: 'Surveillance & Security: Law enforcement uses drones for monitoring and crime prevention.',
    a5: 'Filmmaking & Photography: Drones capture high-resolution aerial footage for movies and events.',
    a6: 'Infrastructure Inspection: Power lines, pipelines, and bridges are monitored using drones.',
    a7: 'Military Applications: Drones are used for reconnaissance, targeting, and combat missions.',
    c2:'',
    videoUrl: 'https://www.youtube.com/watch?v=gE6QHM1wzXw',
    image: 'https://images.unsplash.com/photo-1473968512647-3e447244af8f?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=2070&q=80',
    papers: [
      {
        id: 'drone-paper-1',
        title: 'Learning Deep Sensorimotor Policies for Vision-based Autonomous Drone Racing',
        authors: 'Jiawei Fu et al.',
        year: '2014',
        link: 'https://arxiv.org/pdf/2210.14985',
        abstract: 'Overview of vision-based navigation systems for drones.'
      },
      {
        id: 'drone-paper-2',
        title: 'A Deep Reinforcement Learning Approach to Efficient Drone Handover in Cellular Networks',
        authors: 'Yun Chen et al.',
        year: '2019',
        link: 'https://arxiv.org/pdf/2005.05229',
        abstract: 'A look at using drones for wireless communication networks.'
      },
      {
        id: 'drone-paper-3',
        title: 'Autonomous Drone Racing: A Survey',
        authors: 'Philipp Foehn et al.',
        year: '2021',
        link: 'https://arxiv.org/pdf/2103.08624',
        abstract: 'This survey reviews the state of the art in autonomous drone racing and identifies key research challenges.'
      },
      {
        id: 'drone-paper-4',
        title: 'Deep Reinforcement Learning for Autonomous Drone Racing',
        authors: 'Yunlong Song et al.',
        year: '2021',
        link: 'https://arxiv.org/pdf/2103.08624',
        abstract: 'This paper explores reinforcement learning approaches for autonomous drone racing through challenging environments.'
      },
      {
        id: 'drone-paper-5',
        title: 'Autonomous UAV Navigation Using Deep Learning-Based Computer Vision',
        authors: 'J. Kim et al.',
        year: '2018',
        link: 'https://pdf.sciencedirectassets.com/320039/1-s2.0-S2590005624X0003X/1-s2.0-S2590005624000274/main.pdf?X-Amz-Security-Token=IQoJb3JpZ2luX2VjEOf%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCXVzLWVhc3QtMSJHMEUCIQDhn4dnoBuvS%2BYxcBQQ8vpqrQPMyd9LYHHSr4bRYWfDqgIgLXkXPBLjsIxZ08PesKjQK6oKOUTuYleNl68iCpAy898qswUIbxAFGgwwNTkwMDM1NDY4NjUiDHGyXUMJlKsyivMgjyqQBc8dJ%2Bc8zcwxMpJfVHNdh3oKQRLDuijGJqb5nI0Y8DdUc5E4L6bXMsaAo5o%2BfZSxagPqZZ0905zFbSljxqg%2FK5Fjxcx2HGg5v2QaXZreEG%2FeQESnz1y2C6mb9kABKbbi%2B2mvmLAG69RsyL7wie7hxxaFriVObRSaYMpfVCbt6sJwgvILu%2B%2Bn0uMNMhmYlHuOyUAda%2BuPDZocLkVRosIUwGpM6BInVT4augiDm6qyhwTnY%2FKTBloJFrV591OjdVSBoYekEUqxhKzkl01T7HbHePcylpbxaoH%2FejIcge8LvrDQYQHCMfZhGOq%2F5PCwEUU1m8f3sipB4DIM3ak%2FEFgZnTSvkSG7dAowPJXv%2BfYUAsUedA4S%2FfTfszFYvJxBGaJzz1DcB8nihnBXiK5A6JvM2%2BBQpdABJdAi4yyrd8ID9sPU8nwfdOj%2BYg7pMqXe%2BBuLDbdorgjZPOyTReoZ6kVjAkG6EQKm6hlj08hwMh1x2xg7HUJRDCjWX9n5olr5jjapWCNbSKjhKBnjV1lqr%2FqzqiawYXr6AOtAo%2FEUVDwtGA7UpwHm6d1sh81iHkkehSptDO%2B9KuodSC%2BCZ1IA0q1vhe2W0tT8T31nUIXgSQZsMk4LgS3LSpljAiAbjO6s2chPYmotQhVdlf0jJkBXP72eXFr18qKzbNKehDxaH7CaBykQbfEAYqxI1nie6y8TOIs5cfEc%2FlcKGBFvjWUCGBiV912peJDzyrHlwT1QO9IBqfq5GWNIcFnXXp84jjzRr%2Fj8nCrsg47Bwu7qFfmj%2FCYv9iAYjeS2LI0MgUyW%2BIqS%2B%2F8FFCmTyHpMR2gr8IIHHkHOjWxcaeX9OOtJaErBh3tvubIYJv1USwLSBhZ9QkP7fFf%2BMM%2Fch8AGOrEB%2BpuAE6mHmlyhxez9UfkmRZZQxismBk%2FXDAzxwRCCOzkTPAYzEgY%2FubDTAnoLcw%2FMYv%2Bn5tP47gTpJUktg3hDsLgtoNpgNcw42Ob8rK21UCGzyU5nykNTUK%2B51NjLzjPgYyhypPVR27qbSHkrVn%2F2d7XvXo8l5T7h8sH0qjmT3XFfJUbhbidxC1qjpt9s6NqcM24lddVPZBKmi1BL5WJlFDIX2NhuFTojYz%2FqoXBgmUGX&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20250418T072440Z&X-Amz-SignedHeaders=host&X-Amz-Expires=300&X-Amz-Credential=ASIAQ3PHCVTYYSKGA2ZJ%2F20250418%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=221f8314a0458f38a4d459a59bd461afd51d6927baa8bd4270361e319f9ccaa1&hash=63888ef4dd52f2da4f857f0fc6e4dda46cb286d924649f330089f975bf33abf5&host=68042c943591013ac2b2430a89b270f6af2c76d8dfd086a07176afe7c76c2c61&pii=S2590005624000274&tid=spdf-1ba2031e-3228-454f-9476-1b9748c35355&sid=6185e79e95d3f44c432b9880b0b7cdf7877dgxrqb&type=client&tsoh=d3d3LnNjaWVuY2VkaXJlY3QuY29t&rh=d3d3LnNjaWVuY2VkaXJlY3QuY29t&ua=13085957535151015b5706&rr=93226c80a9e4cd03&cc=in',
        abstract: 'This paper presents a drone system designed for assisting in crop pollination to address declining bee populations.'
      },
      {
        id: 'drone-paper-6',
        title: 'Autonomous UAV Navigation Using Reinforcement Learning',
        authors: 'K. Kang, S. Belkhale, G. Kahn et al.',
        year: '2019',
        link: 'https://arxiv.org/pdf/1901.00533',
        abstract: 'This paper demonstrates how UAVs can learn navigation policies through reinforcement learning techniques.'
      }
    ],
    resources: [
      {
        id: '0',
        title: 'Introduction to ' + 'Drones',
        description: 'Learn the fundamentals of ' + 'Drones',
        link: 'https://uavcoach.com/how-to-fly-a-quadcopter-guide/',
        type: ResourceType.Tutorial
      },
      {
        id: '2',
        title: 'Advanced ' + 'Drones' + ' Concepts',
        description: 'Deep dive into advanced topics and applications',
        link: 'https://onlinecourses.nptel.ac.in/noc20_ae04/preview',
        type: ResourceType.Course
      },
      {
        id: '3',
        title: 'Drones' + ' Fundamentals Video',
        description: 'Video tutorial covering the basics of ' + 'Drones',
        link: 'https://www.youtube.com/watch?v=xmHLiEw-GUU',
        type: ResourceType.Video
      },
      {
        id: '4',
        title: 'Advanced ' + 'Drones' + ' Techniques Video',
        description: 'Deep dive into advanced concepts and applications',
        link: 'https://www.youtube.com/watch?v=L73w5N0SLbw',
        type: ResourceType.Video
      }
    ],
    videoTutorials: [
      {
        id: 'drone-video-1',
        title: 'Drone Flight Basics',
        duration: '10:29',
        thumbnail: 'https://images.unsplash.com/photo-1579829366248-204fe8413f31?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=60',
        videoUrl: 'https://www.youtube.com/watch?v=1GNwMhPwFiE&ab_channel=Murtaza%27sWorkshop-RoboticsandAI',
        description: 'Learn the fundamentals of drone flight controls, safety, and basic maneuvers.'
      },
      {
        id: 'drone-video-2',
        title: 'Advanced Drone Programming',
        duration: '3:33:02',
        thumbnail: 'https://images.unsplash.com/photo-1527977966376-1c8408f9f108?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=60',
        videoUrl: 'https://www.youtube.com/watch?v=LmEcyQnfpDA&ab_channel=Murtaza%27sWorkshop-RoboticsandAI',
        description: 'Explore advanced programming techniques for autonomous drone navigation and obstacle avoidance.'
      }
    ]
  },
  {
    id: '6',
    title: 'Quantum Computing',
    slug: 'quantum-computing',
    shortDescription: 'Computing using quantum-mechanical phenomena',
    description: 'Quantum computing is a type of computation that harnesses the collective properties of quantum states, such as superposition, interference, and entanglement, to perform calculations. It uses quantum bits or qubits which can exist in multiple states simultaneously.',
    overview: 'Quantum computing leverages quantum mechanics principles to perform computations exponentially faster than classical computers for certain problems.',  
    keypoints: 'Quantum computing is based on several fundamental concepts:',  
    p1: 'Qubits: Unlike classical bits, qubits can exist in multiple states simultaneously due to superposition.',  
    p2: 'Superposition: A quantum state where a qubit can represent both 0 and 1 at the same time.',  
    p3: 'Entanglement: A quantum phenomenon where qubits become interconnected, influencing each other instantly.',  
    p4: 'Quantum Gates: Operations that manipulate qubits to perform quantum computations.',  
    p5: 'Quantum Supremacy: The potential ability of quantum computers to solve problems beyond classical computing capabilities.',  
    p6: 'Error Correction: Techniques used to minimize quantum errors due to decoherence and noise.',  
    c1: 'Quantum computing is poised to revolutionize industries by solving complex problems much faster than classical systems.',  
    applications: 'Quantum computing has the potential to transform multiple fields:',  
    a1: "Cryptography: Quantum algorithms like Shor's algorithm can break traditional encryption methods.",  
    a2: "Drug Discovery: Simulating molecular interactions for faster pharmaceutical research.",  
    a3: "Optimization Problems: Solving complex logistical and scheduling problems efficiently.",  
    a4: "Financial Modeling: Enhancing risk analysis and portfolio optimization.",  
    a5: "Artificial Intelligence: Speeding up training and inference of machine learning models.",  
    a6: 'Material Science: Discovering new materials by simulating atomic structures.',  
    a7: 'Weather Forecasting: Improving climate models through complex quantum simulations.',  
    c2:'',
    videoUrl: 'https://www.youtube.com/watch?v=jHoEjvuPoB8',
    image: 'https://images.unsplash.com/photo-1635070041078-e363dbe005cb?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=2070&q=80',
    papers: [
      {
        id: 'qc-paper-1',
        title: 'Quantum Supremacy Using a Programmable Superconducting Processor',
        authors: 'Google AI Quantum and Collaborators',
        year: '2019',
        link: 'https://www.nature.com/articles/s41586-019-1666-5',
        abstract: 'Google\'s quantum supremacy experiment.'
      },
      {
        id: 'qc-paper-2',
        title: 'Quantum Computing in the NISQ era and beyond',
        authors: 'J. Preskill',
        year: '2018',
        link: 'https://arxiv.org/pdf/1801.00862',
        abstract: 'Overview of near-term quantum computing and its limitations.'
      },
      {
        id: 'qc-paper-3',
        title: 'Demonstrating a Quantum Advantage',
        authors: 'F. Arute et al.',
        year: '2019',
        link: 'https://www.nature.com/articles/s41586-019-1666-5',
        abstract: 'This paper demonstrates quantum advantage where a quantum processor performed a target computation significantly faster than the world\'s fastest supercomputer.'
      },
      {
        id: 'qc-paper-4',
        title: 'Quantum Error Correction for Beginners',
        authors: 'S. J. Devitt, K. Nemoto, W. J. Munro',
        year: '2013',
        link: 'https://arxiv.org/pdf/0905.2794',
        abstract: 'An introduction to quantum error correction, a critical component for practical quantum computing.'
      },
      {
        id: 'qc-paper-5',
        title: 'Quantum Machine Learning',
        authors: 'J. Biamonte, P. Wittek, et al.',
        year: '2017',
        link: 'https://www.nature.com/articles/nature23474',
        abstract: 'This review discusses the intersection of quantum computing and machine learning, highlighting potential advantages.'
      },
      {
        id: 'qc-paper-6',
        title: 'Blueprint for a Scalable Photonic Fault-Tolerant Quantum Computer',
        authors: 'T. R. Tan et al.',
        year: '2020',
        link: 'https://arxiv.org/abs/2010.02905',
        abstract: 'This paper outlines a blueprint for building a large-scale fault-tolerant quantum computer using photonic qubits.'
      }
    ],
    resources: [
      {
        id: '0',
        title: 'Introduction to ' + 'Quantum Computing',
        description: 'Learn the fundamentals of ' + 'Quantum Computing',
        link: 'https://www.geeksforgeeks.org/introduction-quantum-computing/',
        type: ResourceType.Tutorial
      },
      {
        id: '1',
        title: 'Byte to Byte on ' + 'Quantum Computing',
        description: 'Learn the fundamentals of ' + 'Quantum Computing',
        link: 'https://www.tutorialspoint.com/quantum-computing/index.htm',
        type: ResourceType.Tutorial
      },
      {
        id: '2',
        title: 'Advanced ' + 'Quantum Computing' + ' Concepts',
        description: 'Deep dive into advanced topics and applications',
        link: 'https://onlinecourses.nptel.ac.in/noc21_cs103/preview',
        type: ResourceType.Course
      },
      {
        id: '3',
        title: 'Quantum Computing' + ' Fundamentals Video',
        description: 'Video tutorial covering the basics of ' + 'Quantum Computing',
        link: 'https://www.youtube.com/watch?v=RQWpF2Gb-gU',
        type: ResourceType.Video
      },
      {
        id: '4',
        title: 'Advanced ' + 'Quantum Computing' + ' Techniques Video',
        description: 'Deep dive into advanced concepts and applications',
        link: 'https://www.youtube.com/watch?v=-1PsQIciMEc',
        type: ResourceType.Video
      }
    ],
    videoTutorials: [
      {
        id: 'qc-video-1',
        title: 'Quantum Computing Explained',
        duration: '1:14:13',
        thumbnail: 'https://images.unsplash.com/photo-1635070041078-e363dbe005cb?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=60',
        videoUrl: 'https://www.youtube.com/embed/Lbndu5EIWvI',
        description: 'A beginner-friendly introduction to quantum computing concepts and applications.'
      },
      {
        id: 'qc-video-2',
        title: 'Programming Quantum Computers',
        duration: '1:28:23',
        thumbnail: 'https://images.unsplash.com/photo-1567427017947-545c5f8d16ad?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=60',
        videoUrl: 'https://www.youtube.com/embed/F_Riqjdh2oM',
        description: 'Learn the basics of programming quantum algorithms using popular quantum computing frameworks.'
      }
    ]
  },
  {
    id: '7',
    title: 'Generative AI',
    slug: 'genai',
    shortDescription: 'AI systems that can generate new content and ideas',
    description: 'Generative AI refers to artificial intelligence systems that can generate new content such as text, images, audio, and video that resembles human-created work. These models use deep learning architectures to identify patterns in existing data and create new outputs that reflect those patterns.',
    overview: 'Generative AI creates new content, including text, images, audio, and videos, by learning patterns from existing data.',  
    keypoints: 'Generative AI relies on deep learning techniques to generate novel content:',  
    p1: 'Neural Networks: Generative models are powered by deep neural networks.',  
    p2: 'GANs (Generative Adversarial Networks): Two neural networks, a generator and a discriminator, compete to improve content generation.',  
    p3: 'VAEs (Variational Autoencoders): AI models that generate new samples by learning latent representations of data.',  
    p4: 'Text Generation: AI models like GPT generate human-like text for various applications.',  
    p5: 'Image Synthesis: AI creates realistic images using models like Stable Diffusion and DALL·E.',  
    p6: 'Music and Video Generation: AI composes music and generates video content automatically.',  
    c1: 'Generative AI is transforming creative industries by producing realistic, high-quality content with minimal human input.',  
    applications: 'Generative AI is revolutionizing various fields with content creation:',  
    a1: 'Content Creation: AI-generated articles, scripts, and marketing materials.',  
    a2: 'Image Editing: AI-powered tools enhance and modify images effortlessly.',  
    a3: 'Music Composition: AI creates original music compositions and soundtracks.',  
    a4: 'Deepfake Technology: AI-generated videos mimic real human faces and voices.',  
    a5: 'Game Development: AI generates realistic characters, textures, and environments.',  
    a6: 'Art Generation: AI creates paintings and digital artwork based on different styles.',  
    a7: 'Virtual Reality & Simulations: AI generates immersive virtual environments for training and entertainment.',      
    c2:'',
    videoUrl: 'https://www.youtube.com/watch?v=rwF-X5STYks',
    image: 'https://images.unsplash.com/photo-1620712943543-bcc4688e7485?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=2070&q=80',
    papers: [
      {
        id: 'genai-paper-1',
        title: 'Generative Adversarial Networks',
        authors: 'Ian J. Goodfellow et al.',
        year: '2014',
        link: 'https://arxiv.org/pdf/1406.2661',
        abstract: 'The original paper introducing GANs, a framework for training generative models.'
      },
      {
        id: 'genai-paper-2',
        title: 'DALL·E 2: Hierarchical Text-Conditional Image Generation with CLIP Latents',
        authors: 'A. Ramesh et al.',
        year: '2022',
        link: 'https://arxiv.org/pdf/2204.06125',
        abstract: 'Research paper on DALL·E 2, a system for creating images from text descriptions.'
      },
      {
        id: 'genai-paper-3',
        title: 'High-Resolution Image Synthesis with Latent Diffusion Models',
        authors: 'Robin Rombach et al.',
        year: '2022',
        link: 'https://arxiv.org/pdf/2112.10752',
        abstract: 'This paper introduces Stable Diffusion, a latent diffusion model for high-resolution image synthesis.'
      },
      {
        id: 'genai-paper-4',
        title: 'StyleGAN: A Style-Based Generator Architecture for Generative Adversarial Networks',
        authors: 'T. Karras, S. Laine, T. Aila',
        year: '2019',
        link: 'https://arxiv.org/pdf/1812.04948',
        abstract: 'This paper presents StyleGAN, a generative adversarial network that enables high-quality image generation with explicit control of different visual features.'
      },
      {
        id: 'genai-paper-5',
        title: 'MuseNet: Generating Musical Compositions with Deep Neural Networks',
        authors: 'OpenAI',
        year: '2019',
        link: 'https://openai.com/research/musenet',
        abstract: 'This paper introduces MuseNet, a deep neural network that can generate 4-minute musical compositions with 10 different instruments.'
      },
      {
        id: 'genai-paper-6',
        title: 'MusicLM: Generating Music From Text',
        authors: 'Andrea Agostinelli et al.',
        year: '2023',
        link: 'https://arxiv.org/pdf/2301.11325',
        abstract: 'This paper presents a model for generating high-fidelity music from text descriptions, trained on a large dataset of music-text pairs.'
      }
    ],
    resources: [
      {
        id: '0',
        title: 'Introduction to ' + 'Generative AI',
        description: 'Learn the fundamentals of ' + 'Generative AI',
        link: 'https://www.w3schools.com/gen_ai/',
        type: ResourceType.Tutorial
      },
      {
        id: '1',
        title: 'Genesis of ' + 'Generative AI',
        description: 'Learn the fundamentals of ' + 'Generative AI',
        link: 'https://www.tutorialspoint.com/gen-ai/index.htm',
        type: ResourceType.Tutorial
      },
      {
        id: '2',
        title: 'Advanced ' + 'Generative AI' + ' Concepts',
        description: 'Deep dive into advanced topics and applications',
        link: 'https://www.cloudskillsboost.google/course_templates/536',
        type: ResourceType.Course
      },
      {
        id: '3',
        title: 'Generative AI' + ' Fundamentals Video',
        description: 'Video tutorial covering the basics of ' + 'Generative AI',
        link: 'https://www.youtube.com/watch?v=nJ25yl34Uqw',
        type: ResourceType.Video
      },
      {
        id: '4',
        title: 'Advanced ' + 'Generative AI' + ' Techniques Video',
        description: 'Deep dive into advanced concepts and applications',
        link: 'https://www.youtube.com/watch?v=pSVk-5WemQ0',
        type: ResourceType.Video
      }
    ],
    videoTutorials: [
      {
        id: 'genai-video-1',
        title: 'Introduction to Generative AI',
        duration: '22:07',
        thumbnail: 'https://images.unsplash.com/photo-1620712943543-bcc4688e7485?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=60',
        videoUrl: 'https://www.youtube.com/watch?v=G2fqAlgmoPo&ab_channel=GoogleCloudTech',
        description: 'An overview of generative AI technologies and their applications in various fields.'
      },
      {
        id: 'genai-video-2',
        title: 'Creating Art with Stable Diffusion',
        duration: '1:00:41',
        thumbnail: 'https://images.unsplash.com/photo-1515405295579-ba7b45403062?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=60',
        videoUrl: 'https://www.youtube.com/watch?v=dMkiOex_cKU&ab_channel=freeCodeCamp.org',
        description: 'Learn how to generate stunning artwork using Stable Diffusion and prompt engineering techniques.'
      }
    ]
  },
  {
    id: '8',
    title: 'Large Language Models',
    slug: 'llms',
    shortDescription: 'Advanced AI models that understand and generate human language',
    description: 'Large Language Models (LLMs) are advanced AI systems trained on vast amounts of text data that can understand, generate, and manipulate human language. These models have billions or even trillions of parameters and can perform various language tasks from translation to creative writing.',
    overview: 'Large Language Models (LLMs) are advanced AI models trained on massive text datasets to understand and generate human-like language.',  
    keypoints: 'LLMs utilize deep learning to process and generate text with high accuracy:',  
    p1: 'Transformer Architecture: Models like GPT and BERT use transformers for efficient text processing.',  
    p2: 'Pretraining & Fine-tuning: LLMs are pretrained on vast datasets and fine-tuned for specific tasks.',  
    p3: 'Contextual Understanding: LLMs analyze text meaning based on surrounding words and phrases.',  
    p4: 'Zero-shot & Few-shot Learning: LLMs generate accurate responses with minimal task-specific examples.',  
    p5: 'Scalability: Larger models with billions of parameters improve text generation capabilities.',  
    p6: 'Ethical Concerns: Issues like bias, misinformation, and responsible AI usage require careful consideration.',  
    c1: 'LLMs are advancing AI-driven communication by enabling smarter, more responsive text-based interactions.',  
    applications: 'LLMs power a wide range of AI-driven language-based applications:',  
    a1: 'Chatbots & Virtual Assistants: AI-powered conversational agents for customer support.',  
    a2: 'Content Generation: AI-generated articles, blogs, and social media content.',  
    a3: 'Code Generation: AI assists in writing and debugging code.',  
    a4: 'Language Translation: AI enhances multilingual communication and translation accuracy.',  
    a5: 'Summarization: AI tools generate concise summaries of long documents.',  
    a6: 'Question Answering: AI-powered systems provide accurate responses to queries.',  
    a7: 'Personalized Recommendations: AI analyzes user text input to suggest relevant content.',      
    c2:'',
    videoUrl: 'https://www.youtube.com/watch?v=zizonToFXDs',
    image: 'https://images.unsplash.com/photo-1677442135968-6d89469c5f97?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=2070&q=80',
    papers: [
      {
        id: 'llm-paper-1',
        title: 'Attention Is All You Need',
        authors: 'A. Vaswani et al.',
        year: '2017',
        link: 'https://arxiv.org/pdf/1706.03762',
        abstract: 'Introduces the Transformer architecture that forms the foundation of modern LLMs.'
      },
      {
        id: 'llm-paper-2',
        title: 'Training language models to follow instructions with human feedback',
        authors: 'Long Ouyang et al.',
        year: '2022',
        link: 'https://arxiv.org/pdf/2203.02155',
        abstract: 'Describes the RLHF technique used to align language models with human preferences.'
      },
      {
        id: 'llm-paper-3',
        title: 'GPT-4 Technical Report',
        authors: 'OpenAI',
        year: '2023',
        link: 'https://arxiv.org/pdf/2303.08774',
        abstract: 'Technical details on GPT-4, a large multimodal model capable of sophisticated reasoning across image and text inputs.'
      },
      {
        id: 'llm-paper-4',
        title: 'Language Models are Few-Shot Learners',
        authors: 'Tom B. Brown et al.',
        year: '2020',
        link: 'https://arxiv.org/pdf/2005.14165',
        abstract: 'Introduces GPT-3, demonstrating that very large language models can perform tasks without task-specific training data.'
      },
      {
        id: 'llm-paper-5',
        title: 'Constitutional AI: Harmlessness from AI Feedback',
        authors: 'Yuntao Bai et al.',
        year: '2022',
        link: 'https://arxiv.org/pdf/2212.08073',
        abstract: 'Introduces a method for training AI systems to be helpful, harmless, and honest without direct human feedback.'
      },
      {
        id: 'llm-paper-6',
        title: 'Llama 2: Open Foundation and Fine-Tuned Chat Models',
        authors: 'Hugo Touvron et al.',
        year: '2023',
        link: 'https://arxiv.org/pdf/2307.09288',
        abstract: 'Presents Llama 2, an open-source large language model available for both research and commercial use.'
      }
    ],
    resources: [
      {
        id: '0',
        title: 'Introduction to ' + 'Large Language Models',
        description: 'Learn the fundamentals of ' + 'Large Language Models',
        link: 'https://www.geeksforgeeks.org/large-language-model-llm/',
        type: ResourceType.Tutorial
      },
      {
        id: '2',
        title: 'Advanced ' + 'Large Language Models' + ' Concepts',
        description: 'Deep dive into advanced topics and applications',
        link: 'https://huggingface.co/learn/llm-course/en/chapter1/1',
        type: ResourceType.Course
      },
      {
        id: '3',
        title: 'Large Language Models' + ' Fundamentals Video',
        description: 'Video tutorial covering the basics of ' + 'Large Language Models',
        link: 'https://www.youtube.com/watch?v=7xTGNNLPyMI',
        type: ResourceType.Video
      },
      {
        id: '4',
        title: 'Advanced ' + 'Large Language Models' + ' Techniques Video',
        description: 'Deep dive into advanced concepts and applications',
        link: 'https://www.youtube.com/watch?v=EWvNQjAaOHw',
        type: ResourceType.Video
      }
    ],
    videoTutorials: [
      {
        id: 'llm-video-1',
        title: 'Understanding Large Language Models',
        duration: '59:47',
        thumbnail: 'https://images.unsplash.com/photo-1677442135968-6d89469c5f97?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=60',
        videoUrl: 'https://www.youtube.com/embed/zjkBMFhNj_g',
        description: 'A deep dive into how large language models work and how they\'re changing AI applications.'
      },
      {
        id: 'llm-video-2',
        title: 'Building Applications with LLMs',
        duration: '29:43',
        thumbnail: 'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=60',
        videoUrl: 'https://www.youtube.com/watch?v=NYSWn1ipbgg&list=PL-Y17yukoyy3zzoMJNkWQuogKbWGyBL-d&ab_channel=DaveEbbelaar',
        description: 'Learn how to integrate large language models into practical applications using modern frameworks.'
      }
    ]
  }
];

export const getAllTopics = () => {
  return topics;
};

export const getTopicBySlug = (slug: string) => {
  return topics.find(topic => topic.slug === slug);
};

export const searchContent = (query: string) => {
  query = query.toLowerCase();
  const results = {
    topics: topics.filter(
      topic => 
        topic.title.toLowerCase().includes(query) || 
        topic.description.toLowerCase().includes(query)
    ),
    papers: topics.flatMap(topic => 
      topic.papers.filter(
        paper => 
          paper.title.toLowerCase().includes(query) || 
          paper.abstract.toLowerCase().includes(query)
      ).map(paper => ({ ...paper, topicSlug: topic.slug }))
    ),
    resources: topics.flatMap(topic => 
      topic.resources.filter(
        resource => 
          resource.title.toLowerCase().includes(query) || 
          resource.description.toLowerCase().includes(query)
      ).map(resource => ({ ...resource, topicSlug: topic.slug }))
    ),
    videoTutorials: topics.flatMap(topic => 
      topic.videoTutorials.filter(
        video => 
          video.title.toLowerCase().includes(query) || 
          video.description.toLowerCase().includes(query)
      ).map(video => ({ ...video, topicSlug: topic.slug }))
    )
  };
  
  return results;
};
