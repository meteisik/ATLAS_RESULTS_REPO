import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_SaffronMantis {

    public void runSaffronMantis() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_MANTIS_FILTER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_SaffronMantisSink()).querySaffronMantis(dataArray);
    }
}

class CWE89_P08_V1_SaffronMantisSink {
    public void querySaffronMantis(String[] dataArray) throws SQLException {
        String data = dataArray[2];
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
