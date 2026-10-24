import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_OnyxRaven {

    public void runOnyxRaven() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_OnyxRavenSource()).loadOnyxRaven();
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

class CWE89_P07_V1_OnyxRavenSource {
    public String loadOnyxRaven() {
        String data;
        data = System.getenv("ONYX_RAVEN_FILTER");
        return data;
    }
}
