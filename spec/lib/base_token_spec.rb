require 'rails_helper'

RSpec.describe TokenAuth::BaseToken do
  let(:entity) do
    entity = double
    entity.stub(:id) { 123 }
    entity.stub(:class) { 'Dummy' }

    entity
  end

  let (:expiration_time) { 1.hour }

  let (:token) { SecureRandom.hex }

  subject { TestBaseToken::Token.new({}) }

  context 'with valid expiration time' do
    describe ".expiration_time_seconds" do
      context "was not set" do
        before do
          subject.class.expiration seconds: nil
        end
        it "has to be nil" do
          expect(subject.class.expiration_time_seconds).to be_nil
        end
      end

      context "was set" do
        before do
          subject.class.expiration seconds: expiration_time
        end

        it "has to be 1 hour" do
          expect(subject.class.expiration_time_seconds).to eq expiration_time
        end
      end
    end
  end

  describe ".build_redis_key" do
    it "has to return string" do
      expect(subject.class.build_redis_key(token)).to be_kind_of(String)
    end

    it "has to ensure key is correct" do
      key = subject.class.build_redis_key(token)
      expect(key).to eq("token_auth:testbasetoken_token:#{token}")
    end
  end

  describe ".generate!" do
    it 'has to ensure stored token is correct'
    it 'has to ensure stored inversed_token is correct'
  end

end
