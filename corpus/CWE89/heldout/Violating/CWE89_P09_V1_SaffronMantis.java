import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_SaffronMantis {

    static class Container {
        public String containerOne;
    }

    public void runSaffronMantis() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_MANTIS_FILTER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_SaffronMantisSink()).querySaffronMantis(dataContainer);
    }
}

class CWE89_P09_V1_SaffronMantisSink {
    public void querySaffronMantis(CWE89_P09_V1_SaffronMantis.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection saffronMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronMantis");
        Statement saffronMantisStatement = null;
        ResultSet saffronMantisRows = null;
        try {
            saffronMantisStatement = saffronMantisConnection.createStatement();
            saffronMantisRows = saffronMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronMantisRows.getRow());
        } finally {
            if (saffronMantisRows != null) {
                saffronMantisRows.close();
            }
            if (saffronMantisStatement != null) {
                saffronMantisStatement.close();
            }
            saffronMantisConnection.close();
        }
    }
}
