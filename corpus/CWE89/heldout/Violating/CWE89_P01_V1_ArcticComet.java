import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V1_ArcticComet {

    public void runArcticComet() throws SQLException {
        String data;
        data = System.getenv("ARCTIC_COMET_FILTER");
        Connection arcticCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticComet");
        Statement arcticCometStatement = null;
        ResultSet arcticCometRows = null;
        try {
            arcticCometStatement = arcticCometConnection.createStatement();
            arcticCometRows = arcticCometStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticCometRows.getRow());
        } finally {
            if (arcticCometRows != null) {
                arcticCometRows.close();
            }
            if (arcticCometStatement != null) {
                arcticCometStatement.close();
            }
            arcticCometConnection.close();
        }
    }
}
