import React from 'react';
import toker from '../../../src';

export default class App extends React.Component {
  state = {
    data: null,
    error: null,
    user: null,
  };

  componentDidMount() {
    toker
      .configure({
        apiUrl: process.env.REACT_APP_API_URL,
        authProviderPaths: {
          facebook: process.env.REACT_APP_FACEBOOK_AUTH_PATH,
          google: process.env.REACT_APP_GOOGLE_AUTH_PATH,
        },
      })
      .catch(error => {
        this.setState({ error });
      });
  }

  oauth = provider => {
    toker
      .oAuthSignIn({ provider })
      .then(user => {
        this.setState({ user });
      })
      .catch(error => {
        this.setState({ error });
      });
  };

  fetchData = () => {
    fetch(process.env.REACT_APP_DEMO_DATA_REQUEST_URL)
      .then(res => {
        return res.json();
      })
      .then(data => {
        this.setState({ data });
      });
  };

  render() {
    const { data, error, user } = this.state;

    return (
      <div>
        <div>
          <button onClick={this.fetchData}>Fetch data</button>
          <button onClick={this.oauth.bind(this, 'facebook')}>
            Facebook auth
          </button>
          <button onClick={this.oauth.bind(this, 'google')}>Google auth</button>
        </div>

        {!!user && <p>Hello, {user.full_name}</p>}
        {!!data && <p>Has {data.length} entries</p>}
        {!!error && <p>{error}</p>}
      </div>
    );
  }
}
