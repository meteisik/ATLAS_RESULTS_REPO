import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_OnyxKestrelSafe {

    public void runOnyxKestrel() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_OnyxKestrelSafeSource()).loadOnyxKestrel();
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

class CWE89_P07_V1_OnyxKestrelSafeSource {
    public String loadOnyxKestrel() {
        String data;
        data = "foo";
        return data;
    }
}
