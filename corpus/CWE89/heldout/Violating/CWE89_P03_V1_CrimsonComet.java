import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V1_CrimsonComet {

    private void queryCrimsonComet(String data) throws SQLException {
        Connection crimsonCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonComet");
        Statement crimsonCometStatement = null;
        ResultSet crimsonCometRows = null;
        try {
            crimsonCometStatement = crimsonCometConnection.createStatement();
            crimsonCometRows = crimsonCometStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(crimsonCometRows.getRow());
        } finally {
            if (crimsonCometRows != null) {
                crimsonCometRows.close();
            }
            if (crimsonCometStatement != null) {
                crimsonCometStatement.close();
            }
            crimsonCometConnection.close();
        }
    }

    public void runCrimsonComet() throws SQLException {
        String data;
        data = System.getenv("CRIMSON_COMET_FILTER");
        queryCrimsonComet(data);
    }
}
