import copy
import unittest
from analyze_timer_publication import bounds,duration,validate_trial


def point(kind,start,end=None,tid=1):
    return {'Kind':kind,'Before':start,'After':start if end is None else end,'NativeTid':tid,'ManagedTid':tid,'Pending':0,'Threads':4}


def trial(profile=2):
    return {'Profile':profile,'Index':0,'Status':'passed','Accepted':True,'RegisteredIncomplete':True,
            'CallbackCompleted':True,'TimerDisposed':profile!=4,'Points':{
                'registered':point(71,1,2),'arm_before':point(72,3,4),'arm_after':point(73,5,6),
                'callback':point(74,10,11,2),'publish_before':point(75,12,13,2),
                'publish_after':point(76,16,17,2),'resume':point(77,20,21,3),
                **({'disposed':point(81,22,23)} if profile!=4 else {}),'end':point(80,24,25)}}


class PublicationTests(unittest.TestCase):
    def test_positive_async_bounds(self):
        r=validate_trial(trial(),1000);self.assertEqual(r['publication_to_observed_resume']['lower_ms'],3)
        self.assertEqual(r['publication_to_observed_resume']['upper_ms'],9)
    def test_race_clamps_lower_bound(self):
        r=trial();r['Points']['resume']=point(77,14,15,3)
        self.assertEqual(validate_trial(r,1000)['publication_to_observed_resume']['lower_ms'],0)
    def test_inline_positive(self):
        r=trial(3);r['Points']['resume']=point(77,14,15,2)
        self.assertTrue(validate_trial(r,1000)['inline_observed'])
    def test_same_tid_without_containment_is_not_inline(self):
        r=trial(3);r['Points']['resume']=point(77,20,21,2)
        self.assertFalse(validate_trial(r,1000)['inline_observed'])
    def test_async_same_thread_contained_rejected(self):
        r=trial();r['Points']['resume']=point(77,14,15,2)
        with self.assertRaises(ValueError):validate_trial(r,1000)
    def test_callback_before_arm_return_allowed(self):
        r=trial();r['Points']['arm_after']=point(73,18,19)
        self.assertEqual(validate_trial(r,1000)['arm_or_enqueue_to_callback']['lower_ms'],0)
    def test_bad_trials_rejected(self):
        changes=[lambda r:r['Points'].pop('resume'),lambda r:r.__setitem__('Accepted',False),
                 lambda r:r.__setitem__('RegisteredIncomplete',False),lambda r:r.__setitem__('CallbackCompleted',False),
                 lambda r:r.__setitem__('TimerDisposed',False),lambda r:r.__setitem__('Status','failed'),
                 lambda r:r['Points']['resume'].__setitem__('NativeTid',0),lambda r:r['Points']['resume'].__setitem__('Kind',99),
                 lambda r:r['Points']['publish_after'].__setitem__('Before',1),lambda r:r['Points']['publish_after'].__setitem__('NativeTid',99)]
        for change in changes:
            with self.subTest(change=change):
                r=trial();change(r)
                with self.assertRaises(ValueError):validate_trial(r,1000)
    def test_queue_has_no_timer_lifetime(self):
        self.assertFalse(validate_trial(trial(4),1000)['inline_observed'])
    def test_delay_bounds(self):
        self.assertEqual(duration(point(78,1,2),point(79,8,9),1000),{'lower_ms':6,'upper_ms':8})
    def test_negative_publication_order_rejected(self):
        with self.assertRaises(ValueError):bounds(point(75,5,6),point(76,4,8),point(77,10),1000)


if __name__=='__main__':unittest.main()
