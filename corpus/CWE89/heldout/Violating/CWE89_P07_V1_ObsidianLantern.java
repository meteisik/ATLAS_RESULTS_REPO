import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_ObsidianLantern {

    public void runObsidianLantern() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_ObsidianLanternSource()).loadObsidianLantern();
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

class CWE89_P07_V1_ObsidianLanternSource {
    public String loadObsidianLantern() {
        String data;
        data = System.getenv("OBSIDIAN_LANTERN_FILTER");
        return data;
    }
}
