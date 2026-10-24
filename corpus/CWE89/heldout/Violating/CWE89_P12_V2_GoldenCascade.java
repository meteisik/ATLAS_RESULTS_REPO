import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_GoldenCascade {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runGoldenCascade() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("GOLDEN_CASCADE_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_GoldenCascadeBase baseObject = new CWE89_P12_V2_GoldenCascadeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_GoldenCascadeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_GoldenCascadeSink extends CWE89_P12_V2_GoldenCascadeBase {
    public void action(String data) throws SQLException {
        Connection goldenCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenCascade");
        Statement goldenCascadeStatement = null;
        ResultSet goldenCascadeRows = null;
        try {
            goldenCascadeStatement = goldenCascadeConnection.createStatement();
            goldenCascadeRows = goldenCascadeStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(goldenCascadeRows.getRow());
        } finally {
            if (goldenCascadeRows != null) {
                goldenCascadeRows.close();
            }
            if (goldenCascadeStatement != null) {
                goldenCascadeStatement.close();
            }
            goldenCascadeConnection.close();
        }
    }
}
