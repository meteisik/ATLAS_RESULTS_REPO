import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V2_ObsidianLanternSafe {
    private static int privateFive = 5;

    private void queryObsidianLantern(String data) throws SQLException {
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

    public void runObsidianLantern() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        queryObsidianLantern(data);
    }
}
