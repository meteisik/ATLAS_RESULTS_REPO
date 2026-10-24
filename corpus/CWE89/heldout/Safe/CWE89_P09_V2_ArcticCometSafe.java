import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_ArcticCometSafe {
    private static boolean privateReturnsTrue() { return true; }

    static class Container {
        public String containerOne;
    }

    public void runArcticComet() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_ArcticCometSafeSink()).queryArcticComet(dataContainer);
    }
}

class CWE89_P09_V2_ArcticCometSafeSink {
    public void queryArcticComet(CWE89_P09_V2_ArcticCometSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
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
