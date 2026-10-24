import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_ObsidianKestrel {

    public void runObsidianKestrel() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_ObsidianKestrelSource()).loadObsidianKestrel();
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

class CWE89_P07_V1_ObsidianKestrelSource {
    public String loadObsidianKestrel() {
        String data;
        data = System.getenv("OBSIDIAN_KESTREL_FILTER");
        return data;
    }
}
