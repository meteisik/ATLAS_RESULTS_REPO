import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_ObsidianKestrelSafe {

    public void runObsidianKestrel() throws SQLException {
        String data;
        data = "foo";
        (new CWE89_P06_V1_ObsidianKestrelSafeSink()).queryObsidianKestrel(data);
    }
}

class CWE89_P06_V1_ObsidianKestrelSafeSink {
    public void queryObsidianKestrel(String data) throws SQLException {
        Connection obsidianKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianKestrel");
        Statement obsidianKestrelStatement = null;
        ResultSet obsidianKestrelRows = null;
        try {
            obsidianKestrelStatement = obsidianKestrelConnection.createStatement();
            obsidianKestrelRows = obsidianKestrelStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(obsidianKestrelRows.getRow());
        } finally {
            if (obsidianKestrelRows != null) {
                obsidianKestrelRows.close();
            }
            if (obsidianKestrelStatement != null) {
                obsidianKestrelStatement.close();
            }
            obsidianKestrelConnection.close();
        }
    }
}
