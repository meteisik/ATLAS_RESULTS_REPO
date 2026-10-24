import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_OnyxRavenSafe {

    static class Container {
        public String containerOne;
    }

    public void runOnyxRaven() throws SQLException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_OnyxRavenSafeSink()).queryOnyxRaven(dataContainer);
    }
}

class CWE89_P09_V1_OnyxRavenSafeSink {
    public void queryOnyxRaven(CWE89_P09_V1_OnyxRavenSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection onyxRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxRaven");
        Statement onyxRavenStatement = null;
        ResultSet onyxRavenRows = null;
        try {
            onyxRavenStatement = onyxRavenConnection.createStatement();
            onyxRavenRows = onyxRavenStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxRavenRows.getRow());
        } finally {
            if (onyxRavenRows != null) {
                onyxRavenRows.close();
            }
            if (onyxRavenStatement != null) {
                onyxRavenStatement.close();
            }
            onyxRavenConnection.close();
        }
    }
}
