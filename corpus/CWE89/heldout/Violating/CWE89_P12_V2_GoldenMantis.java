import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_GoldenMantis {
    private static boolean privateReturnsTrue() { return true; }

    public void runGoldenMantis() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("GOLDEN_MANTIS_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_GoldenMantisBase baseObject = new CWE89_P12_V2_GoldenMantisSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_GoldenMantisBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_GoldenMantisSink extends CWE89_P12_V2_GoldenMantisBase {
    public void action(String data) throws SQLException {
        Connection goldenMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenMantis");
        Statement goldenMantisStatement = null;
        ResultSet goldenMantisRows = null;
        try {
            goldenMantisStatement = goldenMantisConnection.createStatement();
            goldenMantisRows = goldenMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(goldenMantisRows.getRow());
        } finally {
            if (goldenMantisRows != null) {
                goldenMantisRows.close();
            }
            if (goldenMantisStatement != null) {
                goldenMantisStatement.close();
            }
            goldenMantisConnection.close();
        }
    }
}
