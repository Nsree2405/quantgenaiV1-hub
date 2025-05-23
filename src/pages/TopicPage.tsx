import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { FileText, Book, ExternalLink, Download, ChevronRight, ArrowLeft, Brain } from 'lucide-react';
import Navbar from '../components/Navbar';
import VideoPlayer from '../components/VideoPlayer';
import FeedbackForm from '../components/FeedbackForm';
import Chatbot from '../components/Chatbot';
import Quiz from '../components/Quiz';
import { Button } from '@/components/ui/button';
import { getTopicBySlug, Topic, Paper, Resource } from '../utils/mockData';
import { 
  machineLearningQuestions,
  deepLearningQuestions,
  nlpQuestions,
  roboticsQuestions,
  dronesQuestions,
  quantumComputingQuestions,
  genaiQuestions,
  llmsQuestions
} from '../utils/quizData';
import { useToast } from '@/hooks/use-toast';

const TopicPage = () => {
  const { slug } = useParams<{ slug: string }>();
  const [topic, setTopic] = useState<Topic | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isQuizOpen, setIsQuizOpen] = useState(false);
  const navigate = useNavigate();
  const { toast } = useToast();
  
  // Get the appropriate questions based on the topic
  const getQuestionsForTopic = (topicSlug: string) => {
    switch (topicSlug) {
      case 'machine-learning':
        return machineLearningQuestions;
      case 'deep-learning':
        return deepLearningQuestions;
      case 'nlp':
        return nlpQuestions;
      case 'robotics':
        return roboticsQuestions;
      case 'drones':
        return dronesQuestions;
      case 'quantum-computing':
        return quantumComputingQuestions;
      case 'genai':
        return genaiQuestions;
      case 'llms':
        return llmsQuestions;
      default:
        return [];
    }
  };

  useEffect(() => {
    window.scrollTo(0, 0);
    
    if (!slug) {
      navigate('/');
      return;
    }
    
    // Simulate API call to fetch topic
    setIsLoading(true);
    setTimeout(() => {
      const fetchedTopic = getTopicBySlug(slug);
      if (fetchedTopic) {
        setTopic(fetchedTopic);
      } else {
        toast({
          title: "Topic not found",
          description: "The requested topic could not be found.",
          variant: "destructive",
        });
        navigate('/');
      }
      setIsLoading(false);
    }, 500);
  }, [slug, navigate, toast]);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-950">
        <Navbar />
        <div className="pt-24 px-4 min-h-screen flex items-center justify-center">
          <div className="flex flex-col items-center">
            <div className="w-12 h-12 border-4 border-quantum-500 border-t-transparent rounded-full animate-spin mb-4"></div>
            <p className="text-gray-600 dark:text-gray-400">Loading topic...</p>
          </div>
        </div>
      </div>
    );
  }

  if (!topic) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-950">
        <Navbar />
        <div className="pt-24 px-4 min-h-screen flex items-center justify-center">
          <div className="text-center">
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">Topic Not Found</h2>
            <p className="text-gray-600 dark:text-gray-400 mb-6">The requested topic could not be found.</p>
            <Button onClick={() => navigate('/')}>
              <ArrowLeft className="w-4 h-4 mr-2" />
              Return to Home
            </Button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-950">
      <Navbar />
      
      {/* Hero Section */}
      <section className="pt-20">
        <div 
          className="relative h-72 md:h-96 bg-cover bg-center"
          style={{ backgroundImage: `url(${topic.image})` }}
        >
          <div className="absolute inset-0 bg-gradient-to-t from-black to-transparent"></div>
          <div className="absolute bottom-0 left-0 right-0 p-6 md:p-10">
            <div className="container mx-auto">
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5 }}
              >
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={() => navigate(-1)}
                  className="mb-4 bg-white/10 backdrop-blur-sm border-white/20 text-white hover:bg-white/20"
                >
                  <ArrowLeft className="w-4 h-4 mr-2" />
                  Back
                </Button>
                <h1 className="text-3xl md:text-5xl font-bold text-white mb-2">{topic.title}</h1>
                <p className="text-lg text-gray-200 max-w-3xl">{topic.shortDescription}</p>
              </motion.div>
            </div>
          </div>
        </div>
      </section>
      
      {/* Content Section */}
      <section className="py-12 md:py-16 px-4">
        <div className="container mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Main Content */}
            <div className="lg:col-span-2 space-y-8">
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.2 }}
                className="bg-white dark:bg-gray-900 rounded-2xl shadow-md p-6 md:p-8"
              >
                <div className="flex justify-between items-center mb-6">
                  <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Introduction to {topic.title}</h2>
                  {getQuestionsForTopic(slug || '').length > 0 && (
                    <Button
                      onClick={() => setIsQuizOpen(true)}
                      className="flex items-center gap-2"
                    >
                      <Brain className="w-4 h-4" />
                      Take Quiz
                    </Button>
                  )}
                </div>
                
                <div className="mb-8">
                  <VideoPlayer videoUrl={topic.videoUrl} title={`${topic.title} Overview`} />
                </div>
                
                <div className="prose dark:prose-invert max-w-none">
                  <p className="text-gray-700 dark:text-gray-300 text-lg leading-relaxed mb-4">
                    {topic.description}
                  </p>
                  
                  <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-4">
                    {topic.overview}
                  </p>
                  
                  {/* <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-4">
                    Donec euismod, nisl eget ultricies aliquam, est odio lacinia nisi, id malesuada magna eros at justo. 
                    Phasellus nec ipsum vel magna tincidunt consequat. Vivamus vehicula, velit at facilisis lobortis, 
                    dolor nunc tincidunt nunc, eu vestibulum urna nulla vel sapien.
                  </p> */}
                  
                  <h3 className="text-xl font-bold text-gray-900 dark:text-white mt-8 mb-4">Key Concepts</h3>
                  
                  <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-4">
                    {topic.keypoints}
                  </p>
                  
                  <ul className="list-disc pl-6 mb-4 space-y-2">
                    <li className="text-gray-700 dark:text-gray-300">
                      {topic.p1}
                    </li>
                    <li className="text-gray-700 dark:text-gray-300">
                    {topic.p2}
                    </li>
                    <li className="text-gray-700 dark:text-gray-300">
                    {topic.p3}
                    </li>
                    <li className="text-gray-700 dark:text-gray-300">
                    {topic.p4}
                    </li>
                    <li className="text-gray-700 dark:text-gray-300">
                    {topic.p5}
                    </li>
                    <li className="text-gray-700 dark:text-gray-300">
                    {topic.p6}
                    </li>
                  </ul>
                  <p className="text-gray-700 dark:text-gray-300">
                    {topic.c1}
                  </p>
                  
                  <h3 className="text-xl font-bold text-gray-900 dark:text-white mt-8 mb-4">Applications</h3>
                  
                  <p className="text-gray-700 dark:text-gray-300 leading-relaxed mb-4">
                    {topic.applications}
                  </p>
                  <ul className="list-disc pl-6 mb-4 space-y-2">
                    <li className="text-gray-700 dark:text-gray-300">
                      {topic.a1}
                    </li>
                    <li className="text-gray-700 dark:text-gray-300">
                    {topic.a2}
                    </li>
                    <li className="text-gray-700 dark:text-gray-300">
                    {topic.a3}
                    </li>
                    <li className="text-gray-700 dark:text-gray-300">
                    {topic.a4}
                    </li>
                    <li className="text-gray-700 dark:text-gray-300">
                    {topic.a5}
                    </li>
                    <li className="text-gray-700 dark:text-gray-300">
                    {topic.a6}
                    </li>
                    <li className="text-gray-700 dark:text-gray-300">
                    {topic.a7}
                    </li>
                  </ul>
                  <p className="text-gray-700 dark:text-gray-300 leading-relaxed">
                    {topic.c2}
                  </p>
                </div>
              </motion.div>
              
              {/* Research Papers */}
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.3 }}
                className="bg-white dark:bg-gray-900 rounded-2xl shadow-md p-6 md:p-8"
              >
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-6">Research Papers</h2>
                
                <div className="space-y-4">
                  {topic.papers.map((paper: Paper) => (
                    <div 
                      key={paper.id}
                      className="p-4 bg-gray-50 dark:bg-gray-800 rounded-xl hover:shadow-md transition-shadow"
                    >
                      <div className="flex items-center mb-3">
                        <FileText className="w-5 h-5 text-quantum-500 mr-2" />
                        <h3 className="font-medium text-gray-900 dark:text-white">{paper.title}</h3>
                      </div>
                      <p className="text-sm text-gray-500 dark:text-gray-400 mb-2">{paper.authors} ({paper.year})</p>
                      <p className="text-sm text-gray-600 dark:text-gray-300 mb-3">{paper.abstract}</p>
                      <div className="flex items-center">
                        <a 
                          href={paper.link} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          className="inline-flex items-center text-quantum-500 hover:text-quantum-600 text-sm font-medium"
                        >
                          <ExternalLink className="w-4 h-4 mr-1" />
                          <span>View Paper</span>
                        </a>
                        <a 
                          href={paper.link} 
                          className="inline-flex items-center text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300 text-sm font-medium ml-4"
                        >
                          <Download className="w-4 h-4 mr-1" />
                          <span>Download PDF</span>
                        </a>
                      </div>
                    </div>
                  ))}
                </div>
                
                <div className="mt-6 text-center">
                  <Button 
                    variant="outline"
                    onClick={() => navigate(`/papers?topic=${topic.slug}`)}
                  >
                    View All Papers
                    <ChevronRight className="ml-2 h-4 w-4" />
                  </Button>
                </div>
              </motion.div>
            </div>
            
            {/* Sidebar */}
            <div className="lg:col-span-1 space-y-6">
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.4 }}
                className="bg-white dark:bg-gray-900 rounded-2xl shadow-md p-6"
              >
                <h3 className="text-lg font-bold text-gray-900 dark:text-white mb-4">Learning Resources</h3>
                
                <div className="space-y-4">
                  {topic.resources.map((resource: Resource) => (
                    <div 
                      key={resource.id}
                      className="p-4 bg-gray-50 dark:bg-gray-800 rounded-xl"
                    >
                      <div className="flex items-center mb-2">
                        <Book className="w-4 h-4 text-quantum-500 mr-2" />
                        <h4 className="font-medium text-gray-900 dark:text-white text-sm">{resource.title}</h4>
                      </div>
                      <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">Type: {resource.type}</p>
                      <p className="text-xs text-gray-600 dark:text-gray-300 mb-3">{resource.description}</p>
                      <a 
                        href={resource.link} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="inline-flex items-center text-quantum-500 hover:text-quantum-600 text-xs font-medium"
                      >
                        <ExternalLink className="w-3 h-3 mr-1" />
                        <span>Access Resource</span>
                      </a>
                    </div>
                  ))}
                </div>

                <div className="mt-6 text-center">
                  <Button 
                    variant="outline"
                    onClick={() => navigate(`/resources?topic=${topic.slug}`)}
                  >
                    View All Resources
                    <ChevronRight className="ml-2 h-4 w-4" />
                  </Button>
                </div>
              </motion.div>
              
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.5 }}
                className="bg-white dark:bg-gray-900 rounded-2xl shadow-md p-6"
              >
                <h3 className="text-lg font-bold text-gray-900 dark:text-white mb-4">Related Topics</h3>
                
                <ul className="space-y-2">
                  {[
                    { title: 'Machine Learning', slug: 'machine-learning' },
                    { title: 'Deep Learning', slug: 'deep-learning' },
                    { title: 'NLP', slug: 'nlp' },
                    { title: 'Robotics', slug: 'robotics' },
                    { title: 'Drones', slug: 'drones' },
                    { title: 'Quantum Computing', slug: 'quantum-computing' },
                    { title: 'Generative AI', slug: 'genai' },
                    { title: 'Large Language Models', slug: 'llms' }
                  ]
                    .filter(t => t.slug !== topic.slug)
                    .slice(0, 8)
                    .map((relatedTopic, index) => (
                      <li key={index}>
                        <a 
                          href={`/topic/${relatedTopic.slug}`}
                          className="flex items-center p-3 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                        >
                          <ChevronRight className="w-4 h-4 mr-2 text-quantum-500" />
                          <span>{relatedTopic.title}</span>
                        </a>
                      </li>
                    ))
                  }
                </ul>
              </motion.div>
              
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.6 }}
              >
                <FeedbackForm />
              </motion.div>
            </div>
          </div>
        </div>
      </section>
      
      {/* Quiz Component */}
      {getQuestionsForTopic(slug || '').length > 0 && (
        <Quiz
          isOpen={isQuizOpen}
          onClose={() => setIsQuizOpen(false)}
          questions={getQuestionsForTopic(slug || '')}
        />
      )}
      
      {/* Footer */}
      <footer className="bg-gray-900 text-gray-400 py-8">
        <div className="container mx-auto px-4">
          <p className="text-center">© 2024 QuantGenAI. All rights reserved.</p>
        </div>
      </footer>
      
      {/* Chatbot */}
      <Chatbot />
    </div>
  );
};

export default TopicPage;
