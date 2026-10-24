import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_VividPrism {

    static class Container {
        public String containerOne;
    }

    public void runVividPrism() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("VIVID_PRISM_FILTER");
            break;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_VividPrismSink()).queryVividPrism(dataContainer);
    }
}

class CWE89_P09_V2_VividPrismSink {
    public void queryVividPrism(CWE89_P09_V2_VividPrism.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection vividPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividPrism");
        Statement vividPrismStatement = null;
        ResultSet vividPrismRows = null;
        try {
            vividPrismStatement = vividPrismConnection.createStatement();
            vividPrismRows = vividPrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(vividPrismRows.getRow());
        } finally {
            if (vividPrismRows != null) {
                vividPrismRows.close();
            }
            if (vividPrismStatement != null) {
                vividPrismStatement.close();
            }
            vividPrismConnection.close();
        }
    }
}
