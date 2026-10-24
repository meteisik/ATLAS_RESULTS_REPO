import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_OnyxRavenSafe {

    public void runOnyxRaven() throws SQLException {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_OnyxRavenSafeSink()).queryOnyxRaven(dataArray);
    }
}

class CWE89_P08_V1_OnyxRavenSafeSink {
    public void queryOnyxRaven(String[] dataArray) throws SQLException {
        String data = dataArray[2];
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
