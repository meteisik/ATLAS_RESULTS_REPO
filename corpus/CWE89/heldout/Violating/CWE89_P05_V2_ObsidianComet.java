import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V2_ObsidianComet {
    private static int privateFive = 5;

    private String obsidianCometData;

    private void queryObsidianComet() throws SQLException {
        String data = obsidianCometData;
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

    public void runObsidianComet() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("OBSIDIAN_COMET_FILTER");
        } else {
            data = null;
        }
        obsidianCometData = data;
        queryObsidianComet();
    }
}
