import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_ObsidianLanternSafe {

    public void runObsidianLantern() throws SQLException {
        String data;
        data = "foo";
        (new CWE89_P06_V1_ObsidianLanternSafeSink()).queryObsidianLantern(data);
    }
}

class CWE89_P06_V1_ObsidianLanternSafeSink {
    public void queryObsidianLantern(String data) throws SQLException {
        Connection obsidianLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianLantern");
        Statement obsidianLanternStatement = null;
        ResultSet obsidianLanternRows = null;
        try {
            obsidianLanternStatement = obsidianLanternConnection.createStatement();
            obsidianLanternRows = obsidianLanternStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(obsidianLanternRows.getRow());
        } finally {
            if (obsidianLanternRows != null) {
                obsidianLanternRows.close();
            }
            if (obsidianLanternStatement != null) {
                obsidianLanternStatement.close();
            }
            obsidianLanternConnection.close();
        }
    }
}
