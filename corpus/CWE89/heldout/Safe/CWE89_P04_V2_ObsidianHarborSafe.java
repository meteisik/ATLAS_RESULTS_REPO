import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V2_ObsidianHarborSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private String loadObsidianHarbor() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        return data;
    }

    public void runObsidianHarbor() throws SQLException {
        String data = loadObsidianHarbor();
        Connection obsidianHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianHarbor");
        Statement obsidianHarborStatement = null;
        ResultSet obsidianHarborRows = null;
        try {
            obsidianHarborStatement = obsidianHarborConnection.createStatement();
            obsidianHarborRows = obsidianHarborStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(obsidianHarborRows.getRow());
        } finally {
            if (obsidianHarborRows != null) {
                obsidianHarborRows.close();
            }
            if (obsidianHarborStatement != null) {
                obsidianHarborStatement.close();
            }
            obsidianHarborConnection.close();
        }
    }
}
