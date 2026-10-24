import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V2_ObsidianComet {
    private static boolean privateTrue = true;

    private String loadObsidianComet() {
        String data;
        if (privateTrue) {
            data = System.getenv("OBSIDIAN_COMET_FILTER");
        } else {
            data = null;
        }
        return data;
    }

    public void runObsidianComet() throws SQLException {
        String data = loadObsidianComet();
        Connection obsidianCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianComet");
        Statement obsidianCometStatement = null;
        ResultSet obsidianCometRows = null;
        try {
            obsidianCometStatement = obsidianCometConnection.createStatement();
            obsidianCometRows = obsidianCometStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(obsidianCometRows.getRow());
        } finally {
            if (obsidianCometRows != null) {
                obsidianCometRows.close();
            }
            if (obsidianCometStatement != null) {
                obsidianCometStatement.close();
            }
            obsidianCometConnection.close();
        }
    }
}
