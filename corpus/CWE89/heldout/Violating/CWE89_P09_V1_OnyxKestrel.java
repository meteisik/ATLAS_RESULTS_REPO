import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_OnyxKestrel {

    static class Container {
        public String containerOne;
    }

    public void runOnyxKestrel() throws SQLException {
        String data;
        data = System.getenv("ONYX_KESTREL_FILTER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_OnyxKestrelSink()).queryOnyxKestrel(dataContainer);
    }
}

class CWE89_P09_V1_OnyxKestrelSink {
    public void queryOnyxKestrel(CWE89_P09_V1_OnyxKestrel.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection onyxKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxKestrel");
        Statement onyxKestrelStatement = null;
        ResultSet onyxKestrelRows = null;
        try {
            onyxKestrelStatement = onyxKestrelConnection.createStatement();
            onyxKestrelRows = onyxKestrelStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxKestrelRows.getRow());
        } finally {
            if (onyxKestrelRows != null) {
                onyxKestrelRows.close();
            }
            if (onyxKestrelStatement != null) {
                onyxKestrelStatement.close();
            }
            onyxKestrelConnection.close();
        }
    }
}
