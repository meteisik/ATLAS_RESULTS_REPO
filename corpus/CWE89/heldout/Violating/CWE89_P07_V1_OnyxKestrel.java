import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_OnyxKestrel {

    public void runOnyxKestrel() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_OnyxKestrelSource()).loadOnyxKestrel();
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

class CWE89_P07_V1_OnyxKestrelSource {
    public String loadOnyxKestrel() {
        String data;
        data = System.getenv("ONYX_KESTREL_FILTER");
        return data;
    }
}
