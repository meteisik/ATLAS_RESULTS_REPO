import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_ObsidianLotus {

    public void runObsidianLotus() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_ObsidianLotusSource()).loadObsidianLotus();
        Connection obsidianLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianLotus");
        Statement obsidianLotusStatement = null;
        ResultSet obsidianLotusRows = null;
        try {
            obsidianLotusStatement = obsidianLotusConnection.createStatement();
            obsidianLotusRows = obsidianLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(obsidianLotusRows.getRow());
        } finally {
            if (obsidianLotusRows != null) {
                obsidianLotusRows.close();
            }
            if (obsidianLotusStatement != null) {
                obsidianLotusStatement.close();
            }
            obsidianLotusConnection.close();
        }
    }
}

class CWE89_P07_V1_ObsidianLotusSource {
    public String loadObsidianLotus() {
        String data;
        data = System.getenv("OBSIDIAN_LOTUS_FILTER");
        return data;
    }
}
