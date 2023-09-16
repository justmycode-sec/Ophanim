package ophanim;


import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.collaborator.Collaborator;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.intruder.Intruder;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.utilities.Utilities;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

class ComboItem {
    private String text;
    private String value;

    public ComboItem(String value){
            this.text = value;
            this.value =value;
    }

    @Override
    public String toString(){
        return text;
    }
}

class OphanimContextMenuItemsProvider implements ContextMenuItemsProvider{

    MontoyaApi api;
    OphanimExtension oe;
    OphanimContextMenuItemsProvider(MontoyaApi api, OphanimExtension oe){
        this.api = api;
        this.oe = oe;
    }
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event)
    {
        if (event.isFromTool(ToolType.PROXY, ToolType.TARGET, ToolType.LOGGER, ToolType.REPEATER, ToolType.SUITE))
        {
            List<Component> menuItemList = new ArrayList<>();

            JMenuItem sendToOphanim = new JMenuItem("Send to Ophanim");

            HttpRequestResponse requestResponse = event.messageEditorRequestResponse().isPresent() ? event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(0);

            sendToOphanim.addActionListener(l -> oe.createRequestTab(requestResponse.request()));
            menuItemList.add(sendToOphanim);


            return menuItemList;
        }

        return null;
    }
}

class OphanimStateSerializer extends StdSerializer<OphanimState> {

    public OphanimStateSerializer(){
        this(null);
    }

    public OphanimStateSerializer(Class<OphanimState> t){
        super(t);
        //super(t);
    }
    @Override
    public void serialize(OphanimState ophanimState, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeStartObject();
        jsonGenerator.writeStringField("oculusName", ophanimState.getOculusName());
        jsonGenerator.writeStringField("configJSON", ophanimState.getConfigJSON());
        jsonGenerator.writeEndObject();
    }
}

@JsonSerialize(using = OphanimStateSerializer.class)
class OphanimState {
    public String getOculusName() {
        return oculusName;
    }

    public void setOculusName(String oculusName) {
        this.oculusName = oculusName;
    }

    private String oculusName;

    public String getConfigJSON() {
        return configJSON;
    }

    public void setConfigJSON(String configJSON) {
        this.configJSON = configJSON;
    }

    private String configJSON;

    public OphanimState(){

    }
}

@SuppressWarnings("all")
public class OphanimExtension implements BurpExtension, ContextMenuItemsProvider, ExtensionUnloadingHandler {
    public static MontoyaApi gApi;
    private MontoyaApi api;
    private Http http;
    private Logging logging;
    private SiteMap siteMap;
    private Scanner scanner;
    private UserInterface userInterface;
    private Collaborator collaborator;
    private BurpSuite burpSuite;
    private Extension extension;
    private Scope scope;
    private Proxy proxy;
    private Intruder intruder;
    private Persistence persistence;
    private Utilities utilities;

    private HttpRequest httpRequest;
    private HttpResponse httpResponse;
    private HttpRequestResponse httpRequestResponse;
    private JTabbedPane tabs;
    private JTextArea configArea;
    private JComboBox oculusSelection;
    public OphanimState state;
    private boolean devMode;
    private boolean purgeState;


    @Override
    public void initialize(MontoyaApi api){

        this.state = new OphanimState();
        this.api = api;
        this.gApi = api;
        this.devMode = false;
        //this.purgeState = true;
        Ophanim.initOphanim();

        this.api.extension().setName("Ophanim");
        this.api.extension().registerUnloadingHandler(this);

        this.api.userInterface().registerSuiteTab("Ophanim", this.createOphanimTab());
        api.userInterface().registerContextMenuItemsProvider(new OphanimContextMenuItemsProvider(api, this));

        if(purgeState){
            api.persistence().extensionData().setString("STATE", null);
        }

        if(devMode){
            api.logging().logToOutput("[D] Retrieving State...");
        }
        if(this.api.persistence().extensionData().getString("STATE") != null && validateState(this.api.persistence().extensionData().getString("STATE"))){
            if(devMode){
                api.logging().logToOutput("[D] State found.");
            }
            this.restoreState(this.api.persistence().extensionData().getString("STATE"));
        }

    }

    private boolean validateState(String stateString) {
        ObjectMapper mapper = new ObjectMapper();
        try{
            if(devMode){
                this.api.logging().logToOutput("[+] Validating State: ");
                this.api.logging().logToOutput(stateString);
            }
            OphanimState tState = mapper.readValue(stateString, OphanimState.class);
            if((tState != null) && (tState.getOculusName() != null) && (tState.getConfigJSON() != null)){
                if(devMode){
                    this.api.logging().logToOutput("[+] Valid State!");
                }
                return true;
            }
        }catch (Exception e){
            //Log Exception to burp output
            this.api.logging().logToError(e.toString());
        }
        if(devMode){
            this.api.logging().logToOutput("[+] Invalid State!");
        }
        return false;
    }

    public void initOculus(String oculusName){

    }


    private Component createOphanimTab(){
        //1- Tabbed Pane (requests, and config)
        tabs = new JTabbedPane();
        //tabs.add("1", this.createRequestTab());
        tabs.add("Config", this.createConfigTab());
        return tabs;
    }

    public void createRequestTab(HttpRequest httpRequest){
        createRequestTab(httpRequest, null, null);
    }

    public void createRequestTab(HttpRequest httpRequest, HttpRequest unpackedRequest, HttpResponse httpResponse){

        HttpRequestEditor unpackedRequestEditor = api.userInterface().createHttpRequestEditor();
        HttpRequestEditor packedRequestEditor = api.userInterface().createHttpRequestEditor();

        if(unpackedRequest != null){
            unpackedRequestEditor.setRequest(unpackedRequest);
        }

        packedRequestEditor.setRequest(httpRequest);

        HttpResponseEditor responseEditor = api.userInterface().createHttpResponseEditor();
        if(httpResponse != null){
            responseEditor.setResponse(httpResponse);
        }

        JSplitPane component = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        component.setResizeWeight(0.5);

        component.setBottomComponent(responseEditor.uiComponent());

        if(unpackedRequest != null){
            component.setTopComponent(this.createRequestTabUpperHalf(packedRequestEditor, responseEditor, unpackedRequestEditor));
        }else{
            component.setTopComponent(this.createRequestTabUpperHalf(packedRequestEditor, responseEditor));
        }
        component.setBottomComponent(responseEditor.uiComponent());
        tabs.add(String.valueOf(tabs.getTabCount()), component);

    }



    private Component createRequestTabUpperHalf(HttpRequestEditor httpRequest, HttpResponseEditor responseEditor){
        return  createRequestTabUpperHalf(httpRequest, responseEditor, api.userInterface().createHttpRequestEditor());
    }

    private Component createRequestTabUpperHalf(HttpRequestEditor packedRequestEditor, HttpResponseEditor responseEditor, HttpRequestEditor unpackedRequestEditor){

        JButton bPack = new JButton("Pack>>");
        bPack.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                packedRequestEditor.setRequest(Ophanim.packRequest(unpackedRequestEditor.getRequest()));
            }
        });
        JButton bUnpack = new JButton("<<Unpack");
        bUnpack.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                unpackedRequestEditor.setRequest(Ophanim.unpackRequest(packedRequestEditor.getRequest()));
            }
        });
        JButton bSend = new JButton("Send");
        bSend.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Runnable runnable = new Runnable() {
                    @Override
                    public void run() {
                        HttpRequestResponse rr = api.http().sendRequest(packedRequestEditor.getRequest());

                        responseEditor.setResponse(rr.response());
                    }
                };
                packedRequestEditor.setRequest(Ophanim.packRequest(unpackedRequestEditor.getRequest()));
                Thread thread = new Thread(runnable);
                thread.start();
            }
        });
        JPanel topHalf = new JPanel();
        topHalf.setLayout(new GridBagLayout());
        GridBagConstraints c;

        c = new GridBagConstraints();
        //c.fill = GridBagConstraints.BOTH;
        //c.weightx = 0.5;
        //c.gridx = 0;
        c.gridy = 0;
        //c.gridwidth = 1;
        topHalf.add(bPack, c);

        c = new GridBagConstraints();
        //c.weightx = 0.5;
        //c.gridx = 9;
        c.gridy = 0;
        //c.gridwidth = 1;
        //c.gridheight = 1;
        topHalf.add(bSend, c);

        c = new GridBagConstraints();
        //c.weightx = 0.5;
        //c.gridx = 12;
        c.gridy = 0;
        topHalf.add(bUnpack, c);

        c = new GridBagConstraints();
        c.fill = GridBagConstraints.BOTH;
        c.weightx = 1;
        c.weighty = 1;
        //c.gridx = 0;
        c.gridy = 1;
        c.gridheight = GridBagConstraints.REMAINDER;
        //c.gridwidth = 8;//GridBagConstraints.RELATIVE;
        //c.anchor = GridBagConstraints.NORTHWEST;
        topHalf.add(unpackedRequestEditor.uiComponent(), c);


        c = new GridBagConstraints();
        c.fill = GridBagConstraints.BOTH;
        c.weightx = 1;
        c.weighty = 1;
        //c.gridx = 8;
        c.gridy = 1;
        c.gridheight = GridBagConstraints.REMAINDER;
        c.gridwidth = GridBagConstraints.REMAINDER;
        //c.anchor = GridBagConstraints.NORTHEAST;
        topHalf.add(packedRequestEditor.uiComponent(), c);

        return topHalf;
    }



    private void populateOculosList(JComboBox list){
        List<String> oculos = Ophanim.getOculos();
        list.addItem(new ComboItem("None"));
        for(String oculus : oculos){
            list.addItem(new ComboItem(oculus));
        }

        oculusSelection = list;

        OphanimExtension dis = this;

        list.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                String oculusConfig = Ophanim.setOculus(list.getSelectedItem().toString());
                configArea.setText(oculusConfig);
                api.logging().logToOutput("[D] Changing config area...");
                state.setOculusName(list.getSelectedItem().toString());
                state.setConfigJSON(oculusConfig);
                if(dis.devMode){
                    api.logging().logToOutput("[D] Updating state: " + list.getSelectedItem().toString());
                    api.logging().logToOutput("[D] Updating state: " + oculusConfig);

                }

            }
        });
    }
    private Component createConfigTab(){
        /*JComboBox oculosSeclector = new JComboBox();
        JTextArea configEditor = new JTextArea();
        JButton okButton = new JButton("Ok");
        JPanel configTab = new JPanel();
        configTab.add(oculosSeclector);
        configTab.add(configEditor);
        configTab.add(okButton);
        return configTab;*/

        JTextArea chatArea = new JTextArea(8, 20);
        configArea = chatArea;
        chatArea.setEditable(true);
        chatArea.setFocusable(true);
        JScrollPane chatScroll = new JScrollPane(chatArea);
        JPanel chatPanel = new JPanel(new BorderLayout());
        chatPanel.add(new JLabel("Config:", SwingConstants.LEFT), BorderLayout.PAGE_START);
        chatPanel.add(chatScroll);

        JComboBox list = new JComboBox();
        populateOculosList(list);
        JButton sendBtn = new JButton("Ok");
        JPanel inputPanel = new JPanel();
        inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.LINE_AXIS));
        inputPanel.add(list);
        inputPanel.add(sendBtn);
        sendBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String config = chatArea.getText();
                if(!(config.length() == 0)){
                    chatArea.append("\n[+] Oculus config: " + Ophanim.initOculus(config));
                    api.logging().logToOutput("[D]createConfigTab: Updating state: " + config);
                    state.setConfigJSON(config);
                }
            }
        });

        JPanel youLabelPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        youLabelPanel.add(new JLabel("Oculus:"));

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.PAGE_AXIS));
        mainPanel.add(chatPanel);
        mainPanel.add(Box.createVerticalStrut(10));
        mainPanel.add(youLabelPanel);
        mainPanel.add(inputPanel);

        JSplitPane sp = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        sp.setTopComponent(mainPanel);
        sp.setResizeWeight(0.5);

        return sp;


    }

    public void extensionUnloaded(){
        try{

            ObjectMapper mapper = new ObjectMapper();
            SimpleModule module = new SimpleModule();
            module.addSerializer(OphanimState.class, new OphanimStateSerializer());
            mapper.registerModule(module);

            String stateJson = mapper.writeValueAsString(state);
            if(devMode){
                api.logging().logToOutput("[D]extensionUnloaded: Saving state:");
                api.logging().logToOutput(stateJson);
            }
            api.persistence().extensionData().setString("STATE", stateJson);
        }catch (Exception e){
            //Log Exception to burp output
            this.api.logging().logToError(e.getMessage());
        }

    }
    public void restoreState(String stateString){
        ObjectMapper mapper = new ObjectMapper();
        if(devMode){
            api.logging().logToOutput("[D] Attempting State Restore: ");
            api.logging().logToOutput(stateString);
        }
        try{
            state = mapper.readValue(stateString, OphanimState.class);
            this.api.logging().logToOutput(state.toString());
            Ophanim.setOculus(state.getOculusName());
            Ophanim.initOculus(state.getConfigJSON());
            configArea.setText(state.getConfigJSON());
            oculusSelection.setSelectedItem(new ComboItem(state.getOculusName()));

        }catch (Exception e){
            //Log Exception to burp output
            this.api.logging().logToError(e.toString());
        }
        return;

    }
}

