import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_OnyxRavenSafe {

    public void runOnyxRaven() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_OnyxRavenSafeSource()).loadOnyxRaven();
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

class CWE89_P07_V1_OnyxRavenSafeSource {
    public String loadOnyxRaven() {
        String data;
        data = "foo";
        return data;
    }
}
