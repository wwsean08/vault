import LinkComponent from '@ember/routing/link-component';

export default LinkComponent.extend({
  classNames: ['toolbar-button'],
  attributeBindings: ['params'],
  params: null,
});
